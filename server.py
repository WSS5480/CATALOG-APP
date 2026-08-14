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
                "/app.css", "/static/", "/a/", "/welcome",
                "/apple-touch-icon.png", "/icon-192.png", "/icon-512.png",
                "/favicon.png", "/manifest.webmanifest", "/manifest.json")
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
    await _report_base(request)
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


# Tell ETL Space this app's public address, once, so sign-in links and invites
# build themselves — nobody should type a URL the system already knows. Fire
# and forget: a failure costs nothing and the next page view tries again.
_BASE_REPORT = {"value": "", "at": 0.0}


async def _report_base(request):
    try:
        base = _self_base(request)
    except Exception:
        return
    if not base or not ETL_BASE:
        return
    import time as _t
    now = _t.time()
    if _BASE_REPORT["value"] == base and now - _BASE_REPORT["at"] < 3600:
        return
    _BASE_REPORT.update(value=base, at=now)
    try:
        await etl_send("POST", "/api/access/catalog-base",
                       {"base": base, "application": APPLICATION}, request=request)
    except Exception:
        pass


@app.get("/")
async def home(request: Request):
    await _report_base(request)
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


# ---------------------------------------------------------------- invites
#
# /welcome is where an invite link lands: the person chooses their own
# password, once, and is sent to their app's sign-in. The page is served
# signed-out by design — the link IS the credential, verified by ETL, and it
# dies the moment it is used. ASCII only in this literal (it is bytes).

WELCOME_PAGE = b"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Welcome &#8212; set your password</title>
<style>
body{margin:0;background:#f5f6fa;font:15px 'Segoe UI',system-ui,-apple-system,Arial,sans-serif;
  color:#1b2130;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px;
  box-sizing:border-box}
.card{background:#fff;border-radius:16px;box-shadow:0 6px 28px rgba(15,25,55,.12);
  padding:26px 24px;width:min(420px,94vw);box-sizing:border-box}
h1{font-size:18px;margin:0 0 6px;color:#16213f}
p{font-size:13.5px;color:#5a6273;line-height:1.55;margin:0 0 16px}
label{display:block;font-size:11px;font-weight:800;color:#5a6273;text-transform:uppercase;
  letter-spacing:.04em;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;border:1px solid #e3e7f0;border-radius:10px;
  padding:11px 13px;font-size:16px}
button{width:100%;margin-top:18px;border:0;border-radius:999px;background:#e0592a;color:#fff;
  font-weight:800;font-size:15px;padding:13px;cursor:pointer;font-family:inherit}
button:disabled{opacity:.5}
#msg{margin-top:12px;font-size:13px;font-weight:700;display:none;border-radius:10px;padding:10px 12px}
#msg.bad{display:block;background:#fde5e5;color:#8f1d1d}
#msg.good{display:block;background:#dcefe4;color:#0d5b3c}
</style></head><body>
<div class="card">
  <h1>Welcome</h1>
  <p>You have been invited to the catalog. Choose a password &#8212; it belongs to you
     and nobody can look it up, so keep it somewhere safe.</p>
  <label>New password</label><input type="password" id="p1" autocomplete="new-password">
  <label>Type it again</label><input type="password" id="p2" autocomplete="new-password">
  <button id="go" type="button">Set my password</button>
  <div id="msg"></div>
</div>
<script>
(function(){
  var tok=new URLSearchParams(location.search).get('i')||'';
  var msg=document.getElementById('msg'), go=document.getElementById('go');
  function say(t,good){msg.textContent=t;msg.className=good?'good':'bad';}
  if(!tok){say('This link is missing its invite code. Ask for a new invite.');go.disabled=true;}
  go.onclick=function(){
    var a=document.getElementById('p1').value, b=document.getElementById('p2').value;
    if(a.length<8)return say('Choose a password of at least 8 characters.');
    if(a!==b)return say('Those two do not match.');
    go.disabled=true; go.textContent='Setting...';
    fetch('/api/auth/accept-invite',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token:tok,password:a})})
      .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
      .then(function(res){
        if(res.ok&&res.j.ok){
          say('Done. Taking you to sign in...',true);
          setTimeout(function(){location.href='/a/'+(res.j.app||'');},900);
        }else{
          say(res.j.detail||res.j.message||'That did not work. Ask for a new invite.');
          go.disabled=false; go.textContent='Set my password';
        }
      })
      .catch(function(){say('Could not reach the server. Try again.');
        go.disabled=false; go.textContent='Set my password';});
  };
})();
</script></body></html>"""


@app.get("/welcome")
async def welcome_page():
    return Response(WELCOME_PAGE, media_type="text/html",
                    headers={"Cache-Control": "no-cache"})


@app.post("/api/auth/accept-invite")
async def auth_accept_invite(request: Request):
    body = await request.json()
    return await etl_send("POST", "/api/access/invites/accept",
                          {"token": body.get("token", ""),
                           "password": body.get("password", "")})


@app.get("/api/vendor/edits")
async def vendor_edits_list(request: Request):
    return await etl_get("/api/access/vendor-edits", request=request)


@app.post("/api/vendor/edits")
async def vendor_edits_submit(request: Request):
    body = await request.json()
    return await etl_send("POST", "/api/access/vendor-edits", body, request=request)



# ---------------- brand icons, served from code -------------------------------
# The icon images live IN this file (base64), not in the repo — a phone upload
# that drops binaries can never cost the brand its face. These routes are
# declared before the static mount, so they always answer.
import base64 as _b64
from fastapi.responses import Response as _Resp

_BRAND_ICONS = {
    "apple-touch-icon.png": "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",
    "icon-192.png": "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",
    "icon-512.png": "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",
    "favicon.png": "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",
}


def _icon_resp(name: str):
    data = _BRAND_ICONS.get(name)
    if not data:
        raise HTTPException(404, "no such icon")
    return _Resp(content=_b64.b64decode(data), media_type="image/png",
                 headers={"Cache-Control": "public, max-age=86400"})


@app.get("/apple-touch-icon.png")
async def brand_icon_apple():
    return _icon_resp("apple-touch-icon.png")


@app.get("/icon-192.png")
async def brand_icon_192():
    return _icon_resp("icon-192.png")


@app.get("/icon-512.png")
async def brand_icon_512():
    return _icon_resp("icon-512.png")


@app.get("/favicon.png")
async def brand_icon_fav():
    return _icon_resp("favicon.png")


@app.get("/manifest.json")
async def brand_manifest():
    return {"name": "Catalog", "short_name": "Catalog",
            "start_url": "/", "display": "standalone",
            "background_color": "#16294F", "theme_color": "#16294F",
            "icons": [
                {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
                {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"}]}


app.mount("/", StaticFiles(directory="static", html=True), name="static")
