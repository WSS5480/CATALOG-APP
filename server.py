"""Catalog / Order Form app — a standalone service.

It holds no data of its own. It connects to an ETL Space instance over HTTP
(the "connector") and reads whichever datasets this particular app is pointed
at. Run as many copies as you like, each with different datasets:

    ETL_BASE_URL   https://your-etl-space.onrender.com     (required)
    ETL_USER       login user for ETL Space   (default: app)
    ETL_PASSWORD   ETL Space APP_PASSWORD     (or use ETL_API_TOKEN)
    ETL_API_TOKEN  ETL Space API_TOKEN        (preferred over password)

    DS_CATALOG     dataset name that holds products      (required)
    DS_USERS       dataset name that holds stores/users
    DS_VENDORS     dataset name that holds vendors
    DS_FREIGHT     dataset name that holds freight costs

    ORDERS_COLLECTION  where submitted orders are stored (default OrderFormClaud)
    APP_PASSWORD   optional password to open THIS app

Nothing here talks to any BI platform; the credentials stay server-side so the
browser never sees them.
"""
import base64
import json
import os
import secrets

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

ETL_BASE = os.environ.get("ETL_BASE_URL", "").rstrip("/")
ETL_USER = os.environ.get("ETL_USER", "app")
ETL_PASSWORD = os.environ.get("ETL_PASSWORD", "")
ETL_TOKEN = os.environ.get("ETL_API_TOKEN", "")
ORDERS_COLLECTION = os.environ.get("ORDERS_COLLECTION", "OrderFormClaud")

# What this business calls a store. Shown on every label in the UI.
LOCATION_LABEL = os.environ.get("LOCATION_LABEL", "Location")
# Optional regular expression limiting which districts appear in the dropdown.
# Leave unset to show every district in the users dataset. Example: ^9[0-9]{3}$
DISTRICT_FILTER = os.environ.get("DISTRICT_FILTER", "")

# Which catalog this deployment opens by default. Catalogs are configured in
# ETL Space (Apps -> Catalogs), so adding one never means touching Render:
# open this same app with ?catalog=<name> and it serves that catalog instead.
CATALOG_PROFILE = os.environ.get("CATALOG_PROFILE", "")

# which dataset in ETL Space feeds each part of this app
DATASETS = {
    "catalog": os.environ.get("DS_CATALOG", ""),
    "users": os.environ.get("DS_USERS", ""),
    "vendors": os.environ.get("DS_VENDORS", ""),
    "freight": os.environ.get("DS_FREIGHT", ""),
}

app = FastAPI(title="Catalog / Order Form")


class AppAuth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        pw = os.environ.get("APP_PASSWORD", "")
        if pw:
            auth = request.headers.get("Authorization", "")
            ok = False
            if auth.startswith("Basic "):
                try:
                    _, _, supplied = base64.b64decode(auth[6:]).decode().partition(":")
                    ok = secrets.compare_digest(supplied, pw)
                except Exception:
                    ok = False
            if not ok:
                return Response("Authentication required", status_code=401,
                                headers={"WWW-Authenticate": 'Basic realm="Catalog"'})
        return await call_next(request)


app.add_middleware(AppAuth)


def _etl_auth():
    """Credentials for the ETL Space connector (never sent to the browser)."""
    if ETL_TOKEN:
        return {"headers": {"X-Api-Key": ETL_TOKEN}}
    if ETL_PASSWORD:
        return {"auth": (ETL_USER, ETL_PASSWORD)}
    return {}


def _require_config():
    if not ETL_BASE:
        raise HTTPException(500, "ETL_BASE_URL is not set — point this app at your ETL Space.")


SESSION_COOKIE = "catalog_session"
# Pages a signed-out visitor may still reach. Everything else redirects to
# the sign-in screen, so a bookmarked deep link asks who you are first.
PUBLIC_PATHS = ("/login", "/login.html", "/api/auth/", "/healthz", "/favicon.ico",
                "/app.css", "/static/")
REQUIRE_SIGNIN = os.environ.get("REQUIRE_SIGNIN", "1").strip().lower() in ("1", "true", "yes", "on")


def _session_headers(request=None):
    """Pass the signed-in person's session through to ETL Space.

    The browser never talks to ETL directly. This app holds the cookie, and
    forwards the token so ETL can decide for itself who is asking — it verifies
    the signature rather than taking our word for it.
    """
    if request is None:
        return {}
    tok = request.cookies.get(SESSION_COOKIE, "")
    return {"X-Catalog-Session": tok} if tok else {}


def _etl_detail(r) -> str:
    """The reason, in the words the person should read.

    ETL Space already writes plain-English messages. Wrapping them in "ETL
    Space: {"detail": ...}" turns a clear sentence into something that looks
    like a crash — and on the sign-in screen it is the first thing a store
    manager would ever see.
    """
    try:
        body = r.json()
        if isinstance(body, dict) and body.get("detail"):
            return str(body["detail"])[:300]
    except Exception:
        pass
    return f"The data service returned an error ({r.status_code})."


async def etl_get(path: str, params: dict | None = None, request=None):
    _require_config()
    async with httpx.AsyncClient(timeout=120) as c:
        opts = _etl_auth()
        opts["headers"] = dict(opts.get("headers") or {}, **_session_headers(request))
        r = await c.get(f"{ETL_BASE}{path}", params=params or {}, **opts)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, _etl_detail(r))
    return r.json()


async def etl_send(method: str, path: str, payload=None, request=None):
    _require_config()
    async with httpx.AsyncClient(timeout=120) as c:
        opts = _etl_auth()
        opts["headers"] = dict(opts.get("headers") or {}, **_session_headers(request))
        r = await c.request(method, f"{ETL_BASE}{path}", json=payload, **opts)
    if r.status_code >= 400:
        raise HTTPException(r.status_code, _etl_detail(r))
    try:
        return r.json()
    except Exception:
        return {"ok": True}


# ---------------- config the app UI can read ----------------

@app.get("/api/app/config")
async def app_config(catalog: str = ""):
    """What this page is serving.

    A catalog defined in ETL Space wins over the DS_* environment variables, so
    one deployment can serve any number of catalogs. The env vars stay as the
    fallback for a plain single-catalog setup.
    """
    wanted = (catalog or CATALOG_PROFILE or "").strip()
    base = {"etl": ETL_BASE, "datasets": dict(DATASETS), "orders": ORDERS_COLLECTION,
            "locationLabel": LOCATION_LABEL, "districtFilter": DISTRICT_FILTER,
            "catalog": "", "catalogLabel": "", "available": [],
            "source": "env", "configured": bool(ETL_BASE and DATASETS["catalog"])}
    if not ETL_BASE:
        return base
    try:
        prof = await etl_get("/api/app/profile", {"name": wanted})
    except HTTPException:
        return base                      # older ETL Space, or no catalogs yet
    except Exception:
        return base
    st = prof.get("settings") or {}
    base.update({
        "datasets": {k: v for k, v in (prof.get("datasets") or {}).items() if v},
        "catalog": prof.get("key") or "",
        "catalogLabel": prof.get("label") or prof.get("key") or "",
        "available": prof.get("available") or [],
        "locationLabel": st.get("locationLabel") or LOCATION_LABEL,
        "districtFilter": st.get("districtFilter") or DISTRICT_FILTER,
        "orders": st.get("ordersCollection") or ORDERS_COLLECTION,
        "source": "profile",
    })
    base["configured"] = bool(base["datasets"].get("catalog"))
    return base


@app.get("/healthz")
async def healthz():
    return {"ok": True, "etl_configured": bool(ETL_BASE), "catalog": DATASETS["catalog"]}


# ---------------- the app's data calls, proxied to ETL Space ----------------

def _dataset_for(role_or_id: str) -> str:
    """Resolve whatever the page asks for into this app's dataset name."""
    key = (role_or_id or "").lower()
    alias = {
        "catalog": "catalog", "storemapping": "users", "stores": "users",
        "users": "users", "vendorinfolist": "vendors", "vendors": "vendors",
        "ashfreight": "freight", "freight": "freight",
    }
    role = alias.get(key, "catalog")
    return DATASETS.get(role) or DATASETS.get("catalog") or ""


@app.post("/api/app/query/{ident}")
async def query(ident: str, request: Request):
    body = await request.json()
    prof = (request.query_params.get("profile") or body.get("profile")
            or CATALOG_PROFILE or "").strip()
    if prof:
        return await etl_send("POST", f"/api/app/query/{ident}?profile={prof}",
                              {"sql": body.get("sql", "")})
    ds = _dataset_for(ident)
    if not ds:
        raise HTTPException(400, "This app has no dataset configured for that request. "
                                 "Set DS_CATALOG / DS_USERS / DS_VENDORS, or define a "
                                 "catalog in ETL Space under Apps.")
    return await etl_send("POST", f"/api/app/query/{ds}", {"sql": body.get("sql", ""),
                                                           "dataset": ds})


@app.get("/api/app/rows/{ident}")
async def rows(ident: str, request: Request):
    params = dict(request.query_params)
    prof = (params.pop("profile", "") or CATALOG_PROFILE or "").strip()
    if prof:
        # let ETL Space resolve the dataset from the catalog's own mapping
        params["profile"] = prof
        params.pop("dataset", None)
        return await etl_get(f"/api/app/rows/{ident}", params, request=request)
    ds = _dataset_for(ident)
    if not ds:
        raise HTTPException(400, "No dataset configured for that request.")
    params["dataset"] = ds
    return await etl_get(f"/api/app/rows/{ds}", params, request=request)


@app.get("/api/app/freshness")
async def freshness(catalog: str = "", profile: str = ""):
    """When each dataset behind this app was last written, straight from ETL
    Space — so "is this screen stale?" has an answer you can read."""
    prof = (profile or catalog or CATALOG_PROFILE or "").strip()
    sets = DATASETS
    if prof:
        try:
            p = await etl_get("/api/app/profile", {"name": prof})
            sets = {k: v for k, v in (p.get("datasets") or {}).items() if v}
        except Exception:
            sets = DATASETS
    wanted = ",".join(sorted({v for v in sets.values() if v}))
    if not wanted:
        return {"datasets": {}, "roles": {}}
    try:
        data = await etl_get("/api/app/freshness", {"datasets_wanted": wanted})
    except HTTPException as e:
        # older ETL Space that predates this endpoint — say so rather than fail
        return {"datasets": {}, "roles": {}, "unavailable": str(e.detail)[:200]}
    by_ds = data.get("datasets") or {}
    return {"datasets": by_ds,
            "roles": {role: by_ds.get(name) for role, name in sets.items() if name}}


@app.get("/api/app/collections/{coll}/documents/")
async def orders_list(coll: str):
    return await etl_get(f"/api/app/collections/{coll}/documents/")


@app.post("/api/app/collections/{coll}/documents/")
async def orders_create(coll: str, request: Request):
    return await etl_send("POST", f"/api/app/collections/{coll}/documents/",
                          await request.json())


@app.put("/api/app/collections/{coll}/documents/{doc_id}")
async def orders_update(coll: str, doc_id: str, request: Request):
    return await etl_send("PUT", f"/api/app/collections/{coll}/documents/{doc_id}",
                          await request.json())


@app.delete("/api/app/collections/{coll}/documents/{doc_id}")
async def orders_delete(coll: str, doc_id: str):
    return await etl_send("DELETE", f"/api/app/collections/{coll}/documents/{doc_id}")


@app.post("/api/app/workflow/{name}/start")
async def workflow(name: str, request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    return await etl_send("POST", f"/api/app/workflow/{name}/start", payload)


@app.exception_handler(HTTPException)
async def clean_errors(request: Request, exc: HTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


def _page_file() -> str | None:
    """The app's HTML page, whatever it ended up being called.

    Uploading through a phone or browser often renames the file — "index 2.html",
    "index_3.html" and so on — which used to leave the site serving nothing at
    all. Prefer a real index.html, otherwise take the newest index-ish page, and
    fall back to any HTML file in the folder.
    """
    import glob
    exact = os.path.join("static", "index.html")
    if os.path.isfile(exact):
        return exact
    candidates = sorted(glob.glob(os.path.join("static", "index*.htm*")),
                        key=os.path.getmtime, reverse=True)
    if not candidates:
        candidates = sorted(glob.glob(os.path.join("static", "*.htm*")),
                            key=os.path.getmtime, reverse=True)
    return candidates[0] if candidates else None


# ---------------------------------------------------------------- sign in
#
# The browser only ever talks to this app. We hold the session cookie on our
# own domain and forward the signed token to ETL Space server-to-server, using
# a credential that never reaches a browser. Two independent judgements: this
# app decides whether you are signed in, ETL decides what you are entitled to.

@app.post("/api/auth/signin")
async def auth_signin(request: Request):
    body = await request.json()
    data = await etl_send("POST", "/api/access/signin",
                          {"email": body.get("email", ""), "password": body.get("password", "")})
    token = data.pop("token", "")
    resp = JSONResponse(data)
    resp.set_cookie(
        SESSION_COOKIE, token,
        httponly=True,                       # JavaScript cannot read it
        secure=request.url.scheme == "https",
        samesite="lax",                      # not sent from other people's sites
        max_age=int(os.environ.get("SESSION_HOURS", "12") or 12) * 3600,
        path="/",
    )
    return resp


@app.post("/api/auth/change-password")
async def auth_change_password(request: Request):
    body = await request.json()
    return await etl_send("POST", "/api/access/change-password",
                          {"current": body.get("current", ""), "new": body.get("new", "")},
                          request=request)


@app.get("/api/auth/me")
async def auth_me(request: Request):
    if not request.cookies.get(SESSION_COOKIE):
        raise HTTPException(401, "Not signed in.")
    return await etl_get("/api/access/me", request=request)


@app.post("/api/auth/signout")
async def auth_signout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


class RequireSignIn(BaseHTTPMiddleware):
    """Anyone without a session gets the sign-in page.

    The path they wanted is carried through as ?next=, so a bookmarked order
    form asks who you are and then takes you where you were going.
    """
    async def dispatch(self, request, call_next):
        if not REQUIRE_SIGNIN or not ETL_BASE:
            return await call_next(request)
        path = request.url.path
        if path.startswith(PUBLIC_PATHS) or request.cookies.get(SESSION_COOKIE):
            return await call_next(request)
        if path.startswith("/api/"):
            return JSONResponse({"detail": "Please sign in."}, status_code=401)
        nxt = path + (("?" + request.url.query) if request.url.query else "")
        from urllib.parse import quote
        return RedirectResponse(f"/login?next={quote(nxt, safe='')}", status_code=302)


app.add_middleware(RequireSignIn)


@app.get("/login")
async def login_page():
    try:
        with open("static/login.html", "rb") as fh:
            return Response(fh.read(), media_type="text/html")
    except FileNotFoundError:
        return Response("<h1>Sign-in page missing</h1><p>Upload <code>login.html</code> "
                        "to the static folder.</p>", status_code=500, media_type="text/html")


@app.get("/")
async def home():
    page = _page_file()
    if not page:
        return Response(
            "<h1>No page found</h1><p>This app has no HTML file in its "
            "<code>static</code> folder. Upload <code>index.html</code> there "
            "and redeploy.</p>",
            status_code=404, media_type="text/html")
    with open(page, "rb") as fh:
        body = fh.read()
    return Response(body, media_type="text/html",
                    headers={"Cache-Control": "no-cache"})


@app.get("/index.html")
async def home_alias():
    return await home()


app.mount("/", StaticFiles(directory="static", html=True), name="static")
