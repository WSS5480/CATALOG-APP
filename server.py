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
