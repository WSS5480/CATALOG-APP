# =============================================================================
#  CATALOG APP   --   repo WSS5480/CATALOG-APP   --   file  server.py
#  Upload to:  https://github.com/WSS5480/CATALOG-APP/upload/main
#
#  This file belongs to the CATALOG APP and to nothing else. It is NOT part of
#  ETL Space. It holds no data, no database and no ETL code: it reaches ETL
#  Space over HTTP using ETL_BASE_URL and ETL_API_TOKEN, and forwards the
#  signed-in person's session for ETL to verify for itself.
#
#  Both repos contain a file called index.html. Check the folder in the link
#  above before uploading, not just the filename.
# =============================================================================
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
import time
from urllib.parse import quote

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

# Which application this deployment is, as named on the Apps tab. ETL answers
# "what does this person get?" per application, so an order-form deployment set
# to APPLICATION=orders reads its own instance and never the catalog's.
APPLICATION = os.environ.get("APPLICATION", "catalog").strip() or "catalog"

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
# Which app this browser is signing in to, set by visiting that app's own link.
# It is only ever a claim about WHICH app, never about who — ETL still checks
# the password and still decides what the person reaches. The worst a forged
# one can do is send you to a customer whose people list does not name you,
# which is a refusal.
APP_COOKIE = "catalog_app"
# Pages a signed-out visitor may still reach. Everything else redirects to
# the sign-in screen, so a bookmarked deep link asks who you are first.
# "/a/" is how a customer arrives, so it has to be reachable signed out.
PUBLIC_PATHS = ("/login", "/login.html", "/api/auth/", "/healthz", "/favicon.ico",
                "/app.css", "/static/", "/a/")
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
async def app_config(request: Request, catalog: str = ""):
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
    # A signed-in person's own app instance wins over anything set at deploy
    # time, so the page names the customer whose catalog is on screen.
    my = await _my_datasets(request)
    if my is not None and not my.get("ok"):
        # Say why, and do not hand back the deploy-time datasets as though they
        # were this person's. Nothing on screen should imply data it cannot show.
        base.update({"datasets": {}, "configured": False, "source": "session",
                     "reason": my.get("reason") or ""})
        return base
    if my and my.get("ok"):
        base.update({"datasets": my.get("datasets") or {},
                     "catalog": my.get("instance") or "",
                     "catalogLabel": my.get("customer") or "",
                     "source": "session", "configured": bool(my.get("master")),
                     "reason": ""})
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
    """Enough to tell what this deployment will actually do, without a session.

    `catalog_profile_set` is here because a profile named at deploy time used to
    silently override every signed-in person's own datasets, and nothing on this
    page said so.
    """
    return {"ok": True, "service": "catalog-app",
            "etl_configured": bool(ETL_BASE), "application": APPLICATION,
            "catalog": DATASETS["catalog"],
            "catalog_profile_set": bool(CATALOG_PROFILE),
            "catalog_profile": CATALOG_PROFILE or "",
            "require_signin": REQUIRE_SIGNIN,
            "app_link_route": True}


# ---------------- the app's data calls, proxied to ETL Space ----------------

_ALIAS = {
    "catalog": "catalog", "storemapping": "users", "stores": "users",
    "users": "users", "vendorinfolist": "vendors", "vendors": "vendors",
    "ashfreight": "freight", "freight": "freight",
}


def _role_of(role_or_id: str) -> str:
    """Which part of the app is asking — catalog, users, vendors or freight."""
    return _ALIAS.get((role_or_id or "").lower(), "catalog")


def _dataset_for(role_or_id: str) -> str:
    """The env-configured dataset. Only used when there is no session at all."""
    role = _role_of(role_or_id)
    return DATASETS.get(role) or DATASETS.get("catalog") or ""


# The signed-in person's dataset map, asked of ETL rather than fixed at deploy.
# Cached briefly and keyed by session so a change on the Apps tab shows up within
# the minute instead of needing an environment variable edited and a redeploy.
_MY_SETS: dict = {}
_MY_TTL = 60


async def _my_datasets(request: Request):
    """What this person's catalog is made of, according to ETL Space.

    Returns None when there is no session — the ETL screens and any
    single-catalog deployment then fall back to the DS_* variables exactly as
    before. With a session, ETL's answer wins outright: the login decides the
    customer, so one deployment serves all of them.
    """
    tok = request.cookies.get(SESSION_COOKIE, "")
    if not tok or not ETL_BASE:
        return None
    now = time.time()
    hit = _MY_SETS.get(tok)
    if hit and hit[0] > now:
        return hit[1]
    try:
        data = await etl_get("/api/app/my/datasets",
                             {"application": APPLICATION}, request=request)
    except HTTPException:
        return None                      # older ETL Space — fall back to env
    _MY_SETS[tok] = (now + _MY_TTL, data)
    if len(_MY_SETS) > 500:              # keep the cache from growing forever
        for k in [k for k, v in list(_MY_SETS.items()) if v[0] <= now]:
            _MY_SETS.pop(k, None)
    return data


async def _resolve_dataset(ident: str, request: Request) -> str:
    """The dataset behind this request, for this person."""
    role = _role_of(ident)
    my = await _my_datasets(request)
    if my is None:
        return _dataset_for(ident)
    if not my.get("ok"):
        raise HTTPException(400, my.get("reason")
                            or "No catalog is set up for your account yet.")
    ds = (my.get("datasets") or {}).get(role, "")
    if not ds:
        raise HTTPException(400, f"{my.get('customer') or 'Your customer'} has no "
                                 f"{role} dataset set up on the Apps tab.")
    return ds


@app.post("/api/app/query/{ident}")
async def query(ident: str, request: Request):
    body = await request.json()
    my = await _my_datasets(request)
    if my is not None and not my.get("ok"):
        raise HTTPException(400, my.get("reason")
                            or "No catalog is set up for your account yet.")
    prof = "" if my is not None else (request.query_params.get("profile") or body.get("profile")
                                      or CATALOG_PROFILE or "").strip()
    if prof:
        return await etl_send("POST", f"/api/app/query/{ident}?profile={prof}",
                              {"sql": body.get("sql", "")})
    ds = await _resolve_dataset(ident, request)
    if not ds:
        raise HTTPException(400, "This app has no dataset configured for that request. "
                                 "Set it up on the Apps tab in ETL Space.")
    return await etl_send("POST", f"/api/app/query/{ds}", {"sql": body.get("sql", ""),
                                                           "dataset": ds})


def _self_base(request) -> str:
    """This deployment's own https address, as the browser sees it.

    Read from the forwarded headers because behind Render's proxy the raw
    scheme says http, and an http image URL on an https page is blocked as
    mixed content — invisibly, which is the worst way to be wrong.
    """
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def _absolutize_images(data, base: str):
    """Turn /api/images/... into a full URL on this catalog's own domain.

    The flow writes image paths relative on purpose — the data never hard-codes
    a hostname, so it survives a domain change. But the catalog page refuses an
    image URL that does not start with http: 727 freshly hosted photos read as
    "no photo" and the page hid all but the broken ones. This server knows its
    own address, so the rewrite belongs here — the data stays portable and the
    page gets the absolute URLs it insists on.
    """
    if isinstance(data, list):
        for item in data:
            _absolutize_images(item, base)
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and v.startswith("/api/images/"):
                data[k] = base + v
            elif isinstance(v, (list, dict)):
                _absolutize_images(v, base)
    return data


@app.get("/api/app/rows/{ident}")
async def rows(ident: str, request: Request):
    """Rows for the signed-in person.

    Their own app decides which dataset, ahead of any catalog profile named at
    deploy time. That order matters and it used to be the other way round: with
    CATALOG_PROFILE set, every request went to the old profile mapping and
    ignored the session entirely, so somebody could sign in perfectly, be
    entitled to hundreds of rows, and be shown a catalog built from whatever
    dataset that mapping still pointed at — quite possibly one that no longer
    exists. The profile is the fallback now, not the winner.
    """
    params = dict(request.query_params)
    asked = params.pop("profile", "").strip()
    my = await _my_datasets(request)
    if my is not None:
        if not my.get("ok"):
            raise HTTPException(400, my.get("reason")
                                or "No catalog is set up for your account yet.")
        ds = await _resolve_dataset(ident, request)
        params["dataset"] = ds
        return _absolutize_images(await etl_get(f"/api/app/rows/{ds}", params, request=request), _self_base(request))
    prof = (asked or CATALOG_PROFILE or "").strip()
    if prof:
        # no session at all — fall back to the catalog's own mapping
        params["profile"] = prof
        params.pop("dataset", None)
        return _absolutize_images(await etl_get(f"/api/app/rows/{ident}", params, request=request), _self_base(request))
    ds = await _resolve_dataset(ident, request)
    params["dataset"] = ds
    return _absolutize_images(await etl_get(f"/api/app/rows/{ds}", params, request=request), _self_base(request))


@app.get("/api/app/freshness")
async def freshness(request: Request, catalog: str = "", profile: str = ""):
    """When each dataset behind this app was last written, straight from ETL
    Space — so "is this screen stale?" has an answer you can read."""
    prof = (profile or catalog or CATALOG_PROFILE or "").strip()
    sets = DATASETS
    my = await _my_datasets(request)
    if my is not None and not my.get("ok"):
        # Signed in, but ETL cannot place this person in an app.
        #
        # Deliberately NOT "unavailable": the catalog page reads that key as
        # "this ETL Space predates the freshness endpoint" and prints "ETL Space
        # is running an older build" — which is a confident, specific and
        # completely wrong diagnosis of an account that simply has no app yet.
        # A wrong explanation costs more than no explanation, so the stamp says
        # nothing and the real reason travels on its own key.
        return {"datasets": {}, "roles": {}, "reason": (my.get("reason") or "")}
    if my and my.get("ok"):
        sets = my.get("datasets") or DATASETS
        prof = ""
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


# The cached product photos live on ETL Space, but the catalog page asks for
# them as /api/images/... on THIS domain — the flow writes relative paths, and
# relative is right: it means the data never hard-codes a hostname. So this
# route passes an image request through to ETL with the connector's own
# credentials, and tells the browser to keep the file for a day — the filename
# is a hash of the content, so a changed image is a new name, never a stale hit.
_IMG_NAME = None

@app.get("/api/images/{name}")
async def image_passthrough(name: str):
    global _IMG_NAME
    import re
    if _IMG_NAME is None:
        _IMG_NAME = re.compile(r"^[0-9a-f]{8,64}\.(?:jpg|jpeg|png|webp)$")
    if not _IMG_NAME.match(name):
        raise HTTPException(404, "No such image.")
    _require_config()
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.get(f"{ETL_BASE}/api/images/{name}", **_etl_auth())
    if r.status_code >= 400:
        raise HTTPException(404, "No such image.")
    return Response(r.content,
                    media_type=r.headers.get("content-type", "image/jpeg"),
                    headers={"Cache-Control": "public, max-age=86400, immutable"})


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
    """Sign in to one app.

    Which app comes from the cookie the /a/<slug> link set, not from anything
    the sign-in form has to send. That is deliberate: it means the login page
    needs no changes at all, and a customer who arrives through their own link
    signs in to their own app without knowing any of this happened.
    """
    body = await request.json()
    which = (body.get("app") or request.cookies.get(APP_COOKIE, "") or "").strip()
    data = await etl_send("POST", "/api/access/signin",
                          {"email": body.get("email", ""), "password": body.get("password", ""),
                           "app": which})
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


# ---------------------------------------------------------------- owner admin
#
# The catalog owner's Admin page. Every route here is a pass-through to ETL
# Space carrying the signed-in person's session, so this app decides nothing
# about who may do what — ETL reads the token, works out whether they own a
# catalog, and refuses on its own account. Adding a route here can widen what
# a browser can reach but never what a person is entitled to.
#
# RequireSignIn already turns away anyone without a cookie, so by the time a
# request arrives here there is a session to forward.

@app.get("/api/admin/my-catalog")
async def admin_my_catalog(request: Request):
    return await etl_get("/api/access/my-catalog", request=request)


@app.post("/api/admin/my-catalog/{name}")
async def admin_save_my_catalog(name: str, request: Request):
    return await etl_send("POST", f"/api/access/my-catalog/{quote(name, safe='')}",
                          await request.json(), request=request)


@app.get("/api/admin/my-people")
async def admin_my_people(request: Request):
    return await etl_get("/api/access/my-people", request=request)


@app.post("/api/admin/my-people/{email}/password")
async def admin_set_password(email: str, request: Request):
    return await etl_send("POST",
                          f"/api/access/my-people/{quote(email, safe='')}/password",
                          await request.json(), request=request)


@app.post("/api/admin/my-people/{email}/force-reset")
async def admin_force_reset(email: str, request: Request):
    return await etl_send("POST",
                          f"/api/access/my-people/{quote(email, safe='')}/force-reset",
                          None, request=request)


@app.get("/api/admin/users/rows")
async def admin_user_rows(request: Request):
    return await etl_get("/api/access/users/rows", request=request)


@app.post("/api/admin/users/rows")
async def admin_save_user_rows(request: Request):
    """Save the location grid. ETL re-runs every flow that reads the dataset,
    so the catalog reflects the change without waiting for the next upload."""
    return await etl_send("POST", "/api/access/users/rows",
                          await request.json(), request=request)


# Guidance for whoever runs a catalog, added to the page as it is served rather
# than edited into it -- the same trick as the Admin button, and for the same
# reason: admin.html never has to change, and deleting this block removes it
# completely. Everything here is something an OWNER can act on; locking the
# services themselves down lives in ETL Space, where the switches are.
#
# ASCII only in this literal, with HTML entities for the typography. A bytes
# string cannot hold anything else, and the page is served as bytes.
ADMIN_GUIDE = b"""
<style>
#cat-guide{max-width:860px;margin:26px auto;padding:16px 18px;border:1px solid #dde3ee;
  border-left:4px solid #0C447C;border-radius:0 12px 12px 0;background:#f7f9fc;
  font:14px/1.6 'Segoe UI',system-ui,-apple-system,Arial,sans-serif;color:#1b2130}
#cat-guide h3{margin:0 0 4px;font-size:1rem}
#cat-guide p{margin:0 0 10px;color:#68748c;font-size:.88rem}
#cat-guide ol{margin:0 0 4px 20px}
#cat-guide li{padding:3px 0;font-size:.9rem}
#cat-guide b{color:#0C447C}
#cat-guide code{background:#eef2f8;border:1px solid #dde3ee;border-radius:5px;padding:1px 5px}
#cat-guide .note{margin-top:10px;padding:9px 11px;background:#fff8ec;border-left:3px solid #b76b00;
  border-radius:0 8px 8px 0;font-size:.85rem;color:#7a4a00}
@media print{#cat-guide{display:none}}
</style>
<div id="cat-guide">
  <h3>Locking this down before real stores use it</h3>
  <p>In order. Each one is something you can do from this page.</p>
  <ol>
    <li><b>Send people their own link, not this address.</b> Each customer has a sign-in
      link ending <code>/a/&hellip;</code>. It is what makes an email and password belong to
      that customer and to nobody else &mdash; the same address at another customer is a
      different person entirely.</li>
    <li><b>Give every person a password.</b> Anyone showing <i>never set</i> cannot sign in.
      Set one and tell them what it is; it is stored as a one-way hash, so nobody &mdash;
      including you &mdash; can read it back.</li>
    <li><b>Leave &quot;must change&quot; ticked.</b> They choose their own on first sign-in,
      and the one you told them stops working.</li>
    <li><b>Force reset the moment somebody leaves.</b> It takes their password away at once.
      Removing them from the location list does the same thing and is better, because there
      is then no account left to forget about.</li>
    <li><b>Check what a person gets before you trust it.</b> Use <i>Check a person</i> in
      ETL Space rather than signing in as them.</li>
  </ol>
  <div class="note"><b>These are not the only locks.</b> The service-level ones &mdash; a
    password on ETL Space itself, admin endpoints requiring a real session, and the connector
    token &mdash; live in ETL Space under <b>Apps &rarr; Before real stores use this</b>, which
    checks them against the running system and tells you which are still open.</div>
</div>
"""


def _with_admin_guide(body: bytes) -> bytes:
    if b'id="cat-guide"' in body:
        return body
    cut = body.lower().rfind(b"</body>")
    return body + ADMIN_GUIDE if cut == -1 else body[:cut] + ADMIN_GUIDE + body[cut:]


@app.get("/admin")
async def admin_page():
    try:
        with open("static/admin.html", "rb") as fh:
            return Response(_with_admin_guide(fh.read()), media_type="text/html",
                            headers={"Cache-Control": "no-cache"})
    except FileNotFoundError:
        return Response("<h1>Admin page missing</h1><p>Upload <code>admin.html</code> "
                        "to the static folder.</p>", status_code=500, media_type="text/html")


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


@app.get("/a/{slug}")
async def app_link(slug: str, request: Request):
    """One customer's way in.

    Everything this does is remember which app you came for and send you on to
    the sign-in page. It holds no session and grants nothing — but from here on,
    the email and password you type are checked against THIS app's accounts and
    THIS customer's people list, so the same address at another customer is a
    different person with a different password.
    """
    try:
        info = await etl_get(f"/api/apps2/by-slug/{quote(slug, safe='')}")
    except HTTPException as e:
        return Response(
            f"<h1>That link does not match an app</h1><p>{e.detail}</p>"
            "<p>Check the address, or ask for a new link.</p>",
            status_code=404, media_type="text/html")
    if not info.get("ready"):
        missing = ", ".join(info.get("missing_required") or []) or "some of its setup"
        return Response(
            f"<h1>{info.get('name','This app')} is not finished being set up</h1>"
            f"<p>It still needs {missing}. Nobody can sign in until that is done.</p>",
            status_code=503, media_type="text/html")
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(
        APP_COOKIE, info.get("slug") or slug,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        max_age=180 * 24 * 3600,        # outlives the session, so the link is a bookmark
        path="/",
    )
    return resp


@app.get("/login")
async def login_page():
    try:
        with open("static/login.html", "rb") as fh:
            return Response(fh.read(), media_type="text/html")
    except FileNotFoundError:
        return Response("<h1>Sign-in page missing</h1><p>Upload <code>login.html</code> "
                        "to the static folder.</p>", status_code=500, media_type="text/html")


# The Admin link, added to the catalog page as it is served rather than edited
# into it. index.html is a large ported page and every hand-edit to it is a
# chance to lose something; injecting the link here means the catalog file never
# has to change, and removing this block removes the button completely.
# Pinning Sign out is for everybody. The Admin button is not, so it is a
# separate block and the server chooses whether to send it at all.
#
# ASCII only in these literals -- they are bytes, spliced into the page as it is
# served. HTML entities carry anything else.
SIGNOUT_BLOCK = b"""
<style id="cat-signout-css">
/* On a tablet the sign-out button sits in the top bar where a thumb reaches it
   by accident. Pinned bottom-left it is still one tap, but on the opposite
   corner from Admin and away from everything else. Desktop is left alone. */
@media (pointer: coarse), (max-width: 1024px){
  .cat-signout-pinned{
    position: fixed !important;
    left: max(14px, env(safe-area-inset-left)) !important;
    bottom: max(14px, env(safe-area-inset-bottom)) !important;
    top: auto !important; right: auto !important;
    margin: 0 !important;
    z-index: 2147482000 !important;
    box-shadow: 0 3px 14px rgba(12,32,68,.35) !important;
  }
}
@media print{.cat-signout-pinned{display:none !important}}
</style>
<script>
(function(){
  // Find the sign-out control by its words rather than by an id, so this keeps
  // working whatever the catalog page is rebuilt to look like. The header is
  // drawn after sign-in resolves, so this watches for it rather than assuming
  // it is there on load.
  function pinSignOut(){
    var all = document.querySelectorAll('button, a, [role="button"]');
    for (var i = 0; i < all.length; i++){
      var t = (all[i].textContent || '').replace(/\\s+/g, ' ').trim();
      if (/^sign\\s?out$/i.test(t)){
        all[i].classList.add('cat-signout-pinned');
        return true;
      }
    }
    return false;
  }
  if (!pinSignOut()){
    var tries = 0;
    var timer = setInterval(function(){
      if (pinSignOut() || ++tries > 40) clearInterval(timer);   // give up after ~10s
    }, 250);
  }
  if (window.MutationObserver){
    new MutationObserver(function(){ pinSignOut(); })
      .observe(document.documentElement, {childList: true, subtree: true});
  }
})();
</script>
<script id="cat-clear-topright">
(function(){
  // The identity strip (#whoAmI, fixed to the top-right by the page) was
  // sitting on top of the cart button and whatever else lives in that corner.
  // Rather than hand-edit the big catalog page, measure at load: if the strip
  // covers any control in the top-right, slide the strip down until it clears
  // the lowest of them. Runs again on resize; leaves the phone layout alone
  // (the page's own media query already relocates the strip there).
  function clearTopRight(){
    var who = document.getElementById('whoAmI');
    if (!who) return false;
    var cs = getComputedStyle(who);
    if (cs.position !== 'fixed' || cs.display === 'none') return true;
    who.style.top = '';                       // re-measure from the stylesheet position
    var wr = who.getBoundingClientRect();
    if (!wr.width || wr.top > 160) return true;   // hidden, or already moved by the page
    var zoneRight = Math.max(360, wr.width + 80); // how far in from the right edge to look
    var cands = document.querySelectorAll('button, a, [role="button"], [id^="qc"]');
    var maxBottom = 0, hit = false;
    for (var i = 0; i < cands.length; i++){
      var el = cands[i];
      if (el === who || who.contains(el)) continue;
      var r = el.getBoundingClientRect();
      if (!r.width || !r.height) continue;          // not rendered
      if (r.top >= 160) continue;                   // not in the top strip
      if (r.right < innerWidth - zoneRight) continue;   // not in the corner
      if (r.width > innerWidth / 2) continue;       // a whole bar, not a control
      if (r.bottom > maxBottom) maxBottom = r.bottom;
      if (r.left < wr.right + 8 && r.right > wr.left - 8 &&
          r.top < wr.bottom + 8 && r.bottom > wr.top - 8) hit = true;
    }
    if (hit) who.style.top = Math.round(maxBottom + 10) + 'px';
    return true;
  }
  // The strip and the cart button are both drawn by scripts after load, so
  // keep trying briefly rather than assuming they are there on the first look.
  var tries = 0;
  var timer = setInterval(function(){
    if ((clearTopRight() && tries > 14) || ++tries > 30) clearInterval(timer);
  }, 400);
  window.addEventListener('load', clearTopRight);
  var rz;
  window.addEventListener('resize', function(){
    clearTimeout(rz); rz = setTimeout(clearTopRight, 150);
  });
})();
</script>
"""

# No script, no fetch, no display:none. The button used to hide itself and then
# ask the browser whether it was allowed to appear, so any hiccup in that one
# request left an administrator on a page with no way into Admin and nothing
# saying why. The server knows who it is serving before it sends a byte, so it
# decides: this markup reaches nobody who is not entitled to it. A failure now
# costs a missing shortcut instead of looking like a permissions problem.
ADMIN_BUTTON = b"""
<style>
/* The catalog's own orange, not ETL's navy -- this button lives on the
   store's page and should dress like it. Navy here read as a stranger. */
#cat-admin-link{position:fixed;right:16px;bottom:16px;z-index:2147483000;display:inline-block;
  background:#f26a2a;color:#fff;border-radius:999px;padding:11px 17px;font:700 14px 'Segoe UI',
  system-ui,-apple-system,Arial,sans-serif;text-decoration:none;box-shadow:0 3px 14px rgba(140,50,0,.35)}
#cat-admin-link:hover{background:#d95a1f}
@media print{#cat-admin-link{display:none !important}}
</style>
<a id="cat-admin-link" href="/admin">&#9881; Admin</a>
"""


async def _me_scope(request) -> dict:
    """Who is being served, asked of ETL Space server-to-server.

    ETL is the only thing that knows, and it verifies the signed token for
    itself. Anything short of a clear answer comes back empty -- every route
    that matters re-checks its caller anyway, so being wrong here costs a
    shortcut or a redirect, never access.
    """
    if request is None or not request.cookies.get(SESSION_COOKIE) or not ETL_BASE:
        return {}
    try:
        me = await etl_get("/api/access/me", request=request)
    except Exception:
        return {}
    return (me or {}).get("scope") or {}


def _scope_administers(sc: dict) -> bool:
    return sc.get("all") is True or str(sc.get("role") or "") in ("owner", "admin")


async def _may_administer(request) -> bool:
    return _scope_administers(await _me_scope(request))


def _with_admin_launcher(body: bytes, may_administer: bool = False) -> bytes:
    """Pin Sign out for everybody; add the Admin button only where it belongs."""
    if b'id="cat-signout-css"' in body:
        return body
    block = SIGNOUT_BLOCK + (ADMIN_BUTTON if may_administer else b"")
    cut = body.lower().rfind(b"</body>")
    if cut == -1:
        return body + block
    return body[:cut] + block + body[cut:]


@app.get("/")
async def home(request: Request):
    sc = await _me_scope(request)
    # A vendor rep signs in through the same link as everyone else but their
    # page is the editor, not the store catalog. Server-decided, like the
    # Admin button: the browser is never asked to hide anything.
    if str(sc.get("role") or "") == "vendor" and not sc.get("all"):
        return RedirectResponse("/vendor", status_code=302)
    page = _page_file()
    if not page:
        return Response(
            "<h1>No page found</h1><p>This app has no HTML file in its "
            "<code>static</code> folder. Upload <code>index.html</code> there "
            "and redeploy.</p>",
            status_code=404, media_type="text/html")
    with open(page, "rb") as fh:
        body = fh.read()
    return Response(_with_admin_launcher(body, _scope_administers(sc)),
                    media_type="text/html", headers={"Cache-Control": "no-cache"})


@app.get("/index.html")
async def home_alias(request: Request):
    return await home(request)


# ---------------------------------------------------------------- vendor editor
#
# A different page of the same app. Reps reach it automatically after signing
# in; the owner and administrators can open /vendor to see what reps see.
# ETL decides for itself, per request, what this person may read and write --
# this app only chooses which page to draw.

@app.get("/vendor")
async def vendor_page(request: Request):
    sc = await _me_scope(request)
    role = str(sc.get("role") or "")
    if role != "vendor" and not _scope_administers(sc):
        return RedirectResponse("/", status_code=302)
    try:
        with open("static/vendor.html", "rb") as fh:
            body = fh.read()
    except FileNotFoundError:
        return Response("<h1>Vendor editor not installed</h1><p>Upload "
                        "<code>vendor.html</code> to the static folder.</p>",
                        status_code=500, media_type="text/html")
    return Response(body, media_type="text/html",
                    headers={"Cache-Control": "no-cache"})


@app.get("/api/vendor/edits")
async def vendor_edits_list(request: Request):
    return await etl_get("/api/access/vendor-edits", request=request)


@app.post("/api/vendor/edits")
async def vendor_edits_submit(request: Request):
    body = await request.json()
    return await etl_send("POST", "/api/access/vendor-edits", body, request=request)


app.mount("/", StaticFiles(directory="static", html=True), name="static")
