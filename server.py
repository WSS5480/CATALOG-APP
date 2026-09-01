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
import asyncio
import base64
import hashlib
import hmac
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
    # The store list — number, name, district, managers. Falls back to the
    # users dataset, which is where all of that lived before locations became
    # a dataset of their own.
    "locations": os.environ.get("DS_LOCATIONS", "") or os.environ.get("DS_USERS", ""),
    "vendors": os.environ.get("DS_VENDORS", ""),
    "freight": os.environ.get("DS_FREIGHT", ""),
}

app = FastAPI(title="Catalog / Order Form")

# A 37,000-row catalog as raw JSON is a fifteen-megabyte page load; gzipped it
# is under two. The mapping app got this the first time "loads real slow" was
# said out loud — this app should have had it the same day.
from fastapi.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=1024)


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
    "catalog": "catalog",
    # StoreMapping is the store list, and stores are locations now. A customer
    # with no locations dataset is served their users file under this name, so
    # nothing about the older arrangement changes.
    "storemapping": "locations", "stores": "locations", "locations": "locations",
    "users": "users", "vendorinfolist": "vendors", "vendors": "vendors",
    "ashfreight": "freight", "freight": "freight",
}


def _role_of(role_or_id: str) -> str:
    """Which part of the app is asking — catalog, users, locations, vendors, freight."""
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

    The catalog itself is served from THIS app's own store whenever the
    customer has built one on the Builder tab — the first brick of standing
    alone. Everything else, and every customer without a built catalog,
    proxies exactly as before.

    Their own app decides which dataset, ahead of any catalog profile named at
    deploy time. That order matters and it used to be the other way round: with
    CATALOG_PROFILE set, every request went to the old profile mapping and
    ignored the session entirely, so somebody could sign in perfectly, be
    entitled to hundreds of rows, and be shown a catalog built from whatever
    dataset that mapping still pointed at — quite possibly one that no longer
    exists. The profile is the fallback now, not the winner.
    """
    local = await _builder_rows_local(ident, request)
    if local is not None:
        return local
    aux = await _aux_rows_local(ident, request)
    if aux is not None:
        return aux
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
    # A built catalog is served from THIS app — so its freshness comes from
    # here too, not from whatever old dataset the ETL still remembers.
    try:
        if os.environ.get("CATALOG_DATABASE_URL", "").strip():
            who = await _whoami(request)
            sc = (who or {}).get("scope") or {}
            cust = _bslug(str(sc.get("customer") or "")) if str(sc.get("customer") or "").strip() else ""
            if not cust or cust == "x":
                cust = _builder_only_customer()
            if cust:
                from sqlalchemy import text as _t
                with _builder_engine().connect() as c:
                    b = c.execute(_t("select * from cat_built where customer=:c and serving"),
                                  {"c": cust}).mappings().first()
                if b:
                    info = {"dataset": "your built catalog", "rows": b["row_count"],
                            "updated_at": str(b["built_at"])[:19],
                            "updated_by": "Catalog Builder", "update_mode": "builder",
                            "source": "this app's own database"}
                    return {"datasets": {"catalog": info}, "roles": {"catalog": info}}
    except Exception:
        pass
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


# Orders: stored in THIS app's own database when it has one — the ETL is only
# used when no catalog database is connected (the original proxy behaviour).

async def _orders_ready(request: Request):
    """Signed in + a local store to write to, else None (→ proxy as before)."""
    if not os.environ.get("CATALOG_DATABASE_URL", "").strip():
        return None
    try:
        who = await _whoami(request)
    except Exception:
        return None
    if who is None:
        raise HTTPException(401, "Not signed in.")
    sc = who.get("scope") or {}
    cust = _bslug(str(sc.get("customer") or "")) if str(sc.get("customer") or "").strip() else ""
    if not cust or cust == "x":
        cust = _builder_only_customer() or "main"
    return who, cust


@app.get("/api/app/collections/{coll}/documents/")
async def orders_list(coll: str, request: Request):
    ready = await _orders_ready(request)
    if ready is None:
        return await etl_get(f"/api/app/collections/{coll}/documents/")
    who, cust = ready
    if _pending_level(who.get("scope")) < 1:
        raise HTTPException(403, "You do not have access to pending orders.")
    from sqlalchemy import text
    with _builder_engine().connect() as c:
        rows = c.execute(text("select id, content from cat_orders where coll=:o and customer=:c "
                              "order by created_at"), {"o": coll, "c": cust}).all()
    out = []
    for rid, content in rows:
        try:
            body = json.loads(content or "{}")
        except Exception:
            body = {}
        out.append({"id": rid, "content": body})
    return out


@app.post("/api/app/collections/{coll}/documents/")
async def orders_create(coll: str, request: Request):
    payload = await request.json()
    ready = await _orders_ready(request)
    if ready is None:
        return await etl_send("POST", f"/api/app/collections/{coll}/documents/", payload)
    who, cust = ready
    if not (who.get("scope") or {}).get("perms", _PERM_DEFAULT).get("order", True):
        raise HTTPException(403, "You do not have access to the order form.")
    content = (payload or {}).get("content")
    if not isinstance(content, dict):
        content = payload if isinstance(payload, dict) else {}
    content.setdefault("SubmittedBy", who.get("email", ""))
    # Budgets: a location or group past its monthly number still submits, but
    # every line is flagged over budget — and only an administrator can approve.
    try:
        p = _person(str(who.get("email") or ""))
        if p is not None and not p["admin"]:
            notes = _budget_check(_builder_engine(), cust, p, content)
            if notes:
                content["OverBudget"] = "Yes"
                content["BudgetNote"] = "; ".join(notes)[:300]
                if not str(content.get("RegionalApproval") or "").strip():
                    content["RegionalApproval"] = "NEEDED — over budget"
    except Exception:
        pass
    rid = secrets.token_hex(8)
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        c.execute(text("insert into cat_orders(id,coll,customer,content) values(:i,:o,:c,:b)"),
                  {"i": rid, "o": coll, "c": cust, "b": json.dumps(content)})
    return {"id": rid, "content": content}


@app.put("/api/app/collections/{coll}/documents/{doc_id}")
async def orders_update(coll: str, doc_id: str, request: Request):
    payload = await request.json()
    ready = await _orders_ready(request)
    if ready is None:
        return await etl_send("PUT", f"/api/app/collections/{coll}/documents/{doc_id}", payload)
    who, cust = ready
    if _pending_level(who.get("scope")) < 2:
        raise HTTPException(403, "You may look at pending orders, but not change them.")
    content = (payload or {}).get("content")
    if not isinstance(content, dict):
        content = payload if isinstance(payload, dict) else {}
    from sqlalchemy import text
    is_admin = bool((who.get("scope") or {}).get("all")) or bool(who.get("admin"))
    if not is_admin:
        with _builder_engine().connect() as c:
            row = c.execute(text("select content from cat_orders where id=:i and coll=:o "
                                 "and customer=:c"), {"i": doc_id, "o": coll, "c": cust}).first()
        if row is not None:
            try:
                old_c = json.loads(row[0] or "{}")
            except Exception:
                old_c = {}
            if str(old_c.get("OverBudget") or "") == "Yes":
                # the flag and the approval field are the administrator's alone
                content["OverBudget"] = "Yes"
                content["BudgetNote"] = old_c.get("BudgetNote", "")
                content["RegionalApproval"] = old_c.get("RegionalApproval", "NEEDED — over budget")
    with _builder_engine().begin() as c:
        n = c.execute(text("update cat_orders set content=:b, updated_at=current_timestamp "
                           "where id=:i and coll=:o and customer=:c"),
                      {"b": json.dumps(content), "i": doc_id, "o": coll, "c": cust}).rowcount
    if not n:
        raise HTTPException(404, "No such order line.")
    return {"id": doc_id, "content": content}


@app.delete("/api/app/collections/{coll}/documents/{doc_id}")
async def orders_delete(coll: str, doc_id: str, request: Request):
    ready = await _orders_ready(request)
    if ready is None:
        return await etl_send("DELETE", f"/api/app/collections/{coll}/documents/{doc_id}")
    who, cust = ready
    if _pending_level(who.get("scope")) < 3:
        raise HTTPException(403, "You do not have delete access on pending orders.")
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        c.execute(text("delete from cat_orders where id=:i and coll=:o and customer=:c"),
                  {"i": doc_id, "o": coll, "c": cust})
    return {"ok": True}


@app.post("/api/app/workflow/{name}/start")
async def workflow(name: str, request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    # With a local catalog there is no ETL flow to run — the Builder and its
    # feeds keep the data fresh, so "refresh" succeeds by having nothing to do.
    if os.environ.get("CATALOG_DATABASE_URL", "").strip():
        return {"ok": True, "message": "The catalog is served from this app's own database."}
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
    email = str(body.get("email") or "").strip().lower()
    # This app's own people sign in HERE — no ETL involved. Only an email with
    # no local row falls through to the ETL, and only while one is configured.
    p = _person(email)
    # Break-glass: BOOTSTRAP_EMAIL + BOOTSTRAP_PASSWORD on the Environment page
    # always sign in and always arrive as an administrator. This is how the
    # first admin gets in, and how a locked-out admin gets back in — change or
    # remove the variables in Render at any time.
    boot_e = os.environ.get("BOOTSTRAP_EMAIL", "").strip().lower()
    boot_p = os.environ.get("BOOTSTRAP_PASSWORD", "")
    if (boot_e and boot_p and email == boot_e
            and str(body.get("password") or "") == boot_p and _people_on()):
        from sqlalchemy import text as _t
        with _builder_engine().begin() as c:
            if c.execute(_t("select email from cat_people where email=:e"),
                         {"e": email}).first() is None:
                c.execute(_t("insert into cat_people(email,customer,admin) "
                             "values(:e,:c,true)"), {"e": email, "c": _builder_only_customer()})
            else:
                c.execute(_t("update cat_people set admin=true where email=:e"), {"e": email})
        data = {"ok": True, "email": email, "must_change": False}
        token = _local_token(email)
    elif p is not None:
        if not p["pw_hash"]:
            raise HTTPException(401, "No password is set for you yet — ask your administrator.")
        if not _pw_check(str(body.get("password") or ""), p["pw_hash"]):
            raise HTTPException(401, "That is not the password.")
        from sqlalchemy import text as _t
        with _builder_engine().begin() as c:
            c.execute(_t("update cat_people set last_signin=:n where email=:e"),
                      {"n": time.strftime("%Y-%m-%d"), "e": email})
        data = {"ok": True, "email": email, "must_change": bool(p["must_change"])}
        token = _local_token(email)
    else:
        if not ETL_BASE:
            raise HTTPException(401, "No account with that email here. Ask your administrator "
                                     "to add you on the Users tab and set your password.")
        which = (body.get("app") or request.cookies.get(APP_COOKIE, "") or "").strip()
        try:
            data = await etl_send("POST", "/api/access/signin",
                                  {"email": body.get("email", ""),
                                   "password": body.get("password", ""), "app": which})
        except HTTPException as e:
            # A stale app cookie from a deleted app must never lock the door —
            # try again as a plain sign-in, which still works for admins.
            if which and e.status_code in (400, 404):
                data = await etl_send("POST", "/api/access/signin",
                                      {"email": body.get("email", ""),
                                       "password": body.get("password", ""), "app": ""})
            else:
                raise
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
    tok = request.cookies.get(SESSION_COOKIE, "").strip('"')
    if tok.startswith("v1."):
        email = _local_token_email(tok)
        p = _person(email) if email else None
        if p is None:
            raise HTTPException(401, "Not signed in.")
        if not p["pw_hash"] or not _pw_check(str(body.get("current") or ""), p["pw_hash"]):
            raise HTTPException(401, "The current password is not right.")
        new = str(body.get("new") or "")
        if len(new) < 8:
            raise HTTPException(400, "Passwords need at least 8 characters.")
        from sqlalchemy import text as _t
        with _builder_engine().begin() as c:
            c.execute(_t("update cat_people set pw_hash=:h, must_change=false where email=:e"),
                      {"h": _pw_make(new), "e": email})
        return {"ok": True, "message": "Password changed."}
    return await etl_send("POST", "/api/access/change-password",
                          {"current": body.get("current", ""), "new": body.get("new", "")},
                          request=request)


@app.get("/api/auth/me")
async def auth_me(request: Request):
    if not request.cookies.get(SESSION_COOKIE):
        raise HTTPException(401, "Not signed in.")
    who = await _whoami(request)
    if who is None:
        raise HTTPException(401, "Not signed in.")
    if who.get("local"):
        return {"email": who["email"], "admin": who["admin"],
                "must_change": who["must_change"], "scope": who["scope"]}
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
  <p>In order. Everything here happens on this page &mdash; users, passwords, groups and
    budgets all live in this app&#39;s own database.</p>
  <ol>
    <li><b>Send everyone to one address:</b> <code>/login</code> on this site. Their email and
      the password you set is all they need &mdash; there are no per-customer links any more.</li>
    <li><b>Give every person a password.</b> Anyone showing <i>never set</i> cannot sign in.
      Set one on the Passwords tab and tell them what it is; it is stored as a one-way hash,
      so nobody &mdash; including you &mdash; can read it back.</li>
    <li><b>Leave &quot;must change&quot; ticked.</b> They choose their own on first sign-in,
      and the one you told them stops working.</li>
    <li><b>Force reset the moment somebody leaves</b> &mdash; or better, press &#10005; on
      their row on the Users tab: sign-in, catalog access and ordering all end at once, and
      no account is left to forget about.</li>
    <li><b>Give access to groups, not people.</b> Vendor reach, tabs and budgets set on a
      group cover everyone in it and cascade into groups inside it; a person&#39;s own row
      is only for exceptions.</li>
    <li><b>Keep your own way back in.</b> <code>BOOTSTRAP_EMAIL</code> and
      <code>BOOTSTRAP_PASSWORD</code> on the service&#39;s Environment page in Render always
      sign in as an administrator &mdash; your answer to a forgotten admin password. Change
      them there whenever you like.</li>
  </ol>
  <div class="note"><b>Two locks live outside this page,</b> both on the Environment page in
    Render: <code>SESSION_SECRET</code> (any long random string, so sessions survive a
    redeploy and only your server can mint them) and the <code>SMTP_*</code> +
    <code>ALERT_EMAIL</code> variables, which turn on the emails that warn you when a feed
    breaks or a file stops matching the schema.</div>
</div>
"""


def _with_admin_guide(body: bytes) -> bytes:
    if b'id="cat-guide"' in body:
        return body
    cut = body.lower().rfind(b"</body>")
    return body + ADMIN_GUIDE if cut == -1 else body[:cut] + ADMIN_GUIDE + body[cut:]



# Column names reach the admin page exactly as the dataset spells them —
# store_name, district_manager_email. The page file predates this concern, so
# the server dresses it on the way out: a script that rewrites raw snake_case
# titles into human words wherever they show as text. Display only — the data
# keys underneath are untouched, so editing and saving still use real names.

# The Admin page predates the Users panel, so the panel is added at the door:
# Locations goes away, People becomes Users, and the same grant rows that the
# ETL Apps tab draws appear here — both fed by the one engine in ETL Space.
USERS_PANEL = """
<style id="cat-users-css">
#ial-users{padding:14px 0 18px}
#ial-users table{width:100%;border-collapse:collapse;font-size:13px;min-width:620px}
#ial-users th{text-align:left;padding:6px 8px;color:#5a6273;font-weight:700;font-size:12px}
#ial-users td{padding:6px 8px;border-top:1px solid #e6e8ee;vertical-align:top}
#ial-users select{max-width:170px;font-size:13px;padding:4px}
#ial-users .ial-bar{display:flex;gap:14px;flex-wrap:wrap;align-items:end;margin-bottom:12px}
#ial-users .ial-f{display:flex;flex-direction:column;gap:3px;font-size:12px;color:#5a6273}
#ial-users button{padding:6px 12px;border:1px solid #d1d5db;border-radius:7px;background:#fff;cursor:pointer;font-size:13px}
#ial-users .ial-add{background:#16294f;color:#fff;border-color:#16294f;font-weight:600}
#ial-users .ial-wrap{overflow-x:auto}
</style>
<script id="cat-users-panel">
(function(){
  var D=null, VALS={};
  function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function human(s){return String(s||'').split('_').filter(Boolean)
    .map(function(w){return w.toLowerCase()==='id'?'ID':w.charAt(0).toUpperCase()+w.slice(1);}).join(' ');}
  function opts(list,cur,blank){
    return '<option value="">'+esc(blank)+'</option>'+(list||[]).map(function(v){
      return '<option value="'+esc(v)+'"'+(String(v)===String(cur||'')?' selected':'')+'>'+esc(v)+'</option>';
    }).join('');
  }
  function vals(ds,col){
    var k=ds+'|'+col;
    if(VALS[k])return Promise.resolve(VALS[k]);
    if(!ds||!col)return Promise.resolve([]);
    return fetch('/api/admin/app-values?dataset='+encodeURIComponent(ds)+'&column='+encodeURIComponent(col),
      {credentials:'same-origin'}).then(function(r){return r.ok?r.json():{values:[]};})
      .then(function(j){VALS[k]=j.values||[];return VALS[k];}).catch(function(){return [];});
  }
  function save(){
    return fetch('/api/admin/app-users',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({groups:D.groups,grants:D.grants,
        extra_people:D.extra_people||[]})}).then(load);
  }
  function draw(){
    var host=document.getElementById('ial-users'); if(!host||!D)return;
    var ucols=(D.user_columns||[]).map(function(c){return {v:c,t:human(c)};});
    function colSel(id,cur){
      return '<select data-ial="'+id+'"><option value="">- choose -</option>'
        +ucols.map(function(c){
          return '<option value="'+esc(c.v)+'"'+(c.v===cur?' selected':'')+'>'+esc(c.t)+'</option>';
        }).join('')+'</select>';
    }
    host.innerHTML='<h3 style="margin:0 0 10px;font-size:15px">Access grants</h3>'
      +'<div class="ial-bar">'
      +'<label class="ial-f">Group 1 column'+colSel('g1',D.groups.g1||'')+'</label>'
      +'<label class="ial-f">Group 2 column'+colSel('g2',D.groups.g2||'')+'</label></div>'
      +'<div class="ial-wrap"><table><thead><tr><th>Group 1</th><th>Group 2</th><th>User</th>'
      +'<th>Column</th><th>Rows</th><th></th></tr></thead><tbody data-ial="rows">'
      +'<tr><td colspan="6">Loading...</td></tr></tbody></table></div>'
      +'<div style="margin-top:10px"><button class="ial-add" data-ial="add">+ New grant access</button> '
      +'<span style="font-size:12px;color:#6b7280">Fill only as far as you need - naming a user '
      +'overrules their group.</span></div>';
    var rows=D.grants||[];
    Promise.all(rows.map(function(g){return vals(D.catalog_dataset,g.column);})).then(function(rv){
      var body=host.querySelector('[data-ial="rows"]'); if(!body)return;
      if(!rows.length){
        body.innerHTML='<tr><td colspan="6" style="color:#6b7280">Nobody has access yet.</td></tr>';
        return;
      }
      body.innerHTML=rows.map(function(g,i){
        var chosen=(g.values||[]).map(String);
        var n=chosen.length;
        var word=n?(g.exclude?('all except '+n):(n===1?'1 selected':n+' selected')):'— any —';
        var pv=g.column
          ? '<details class="ial-ms"><summary style="cursor:pointer;border:1px solid #d1d5db;'
            +'border-radius:7px;padding:4px 9px;font-size:13px;background:#fff;max-width:180px;'
            +'overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(word)+' ▾</summary>'
            +'<div style="position:absolute;z-index:60;background:#fff;border:1px solid #d1d5db;'
            +'border-radius:9px;padding:9px;box-shadow:0 10px 26px rgba(0,0,0,.25);'
            +'max-height:300px;overflow:auto;min-width:220px">'
            +'<input placeholder="filter" data-ial="vfilter" style="width:100%;margin:0 0 7px;'
            +'border:1px solid #d1d5db;border-radius:6px;padding:5px 7px;font-size:12.5px">'
            +'<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:0 0 7px">'
            +'<button data-ial="vall" data-i="'+i+'" style="padding:2px 8px;font-size:11.5px">All</button>'
            +'<button data-ial="vnone" data-i="'+i+'" style="padding:2px 8px;font-size:11.5px">None</button>'
            +'<label style="display:flex;gap:5px;align-items:center;font-size:11.5px;cursor:pointer">'
            +'<input type="checkbox" data-ial="vexc" data-i="'+i+'"'+(g.exclude?' checked':'')+'>'
            +'all <b>except</b> ticked</label></div>'
            +(rv[i]||[]).map(function(v){
              return '<label style="display:flex;gap:7px;align-items:center;padding:3px 2px;'
                +'font-size:12.5px;cursor:pointer;white-space:nowrap">'
                +'<input type="checkbox" data-ial="vtick" data-i="'+i+'" value="'+esc(v)+'"'
                +(chosen.indexOf(String(v))>=0?' checked':'')+'>'+esc(v)+'</label>';
            }).join('')
            +'</div></details>'
          : '<span style="color:#6b7280">every row</span>';
        return '<tr>'
          +'<td><select data-ial="group1" data-i="'+i+'">'+opts(D.group1_values,g.group1,'- any -')+'</select></td>'
          +'<td><select data-ial="group2" data-i="'+i+'">'+opts(D.group2_values,g.group2,'- any -')+'</select></td>'
          +'<td><select data-ial="user" data-i="'+i+'">'+opts(D.people,g.user,'- any -')+'</select></td>'
          +'<td><select data-ial="column" data-i="'+i+'">'+opts(D.catalog_columns,g.column,'- any -')+'</select></td>'
          +'<td>'+pv+'</td>'
          +'<td><button data-ial="drop" data-i="'+i+'">X</button></td></tr>';
      }).join('');
    });
    drawExtras(host);
  }
  // Typed-in people and stores. Same rows the ETL screen edits — one store,
  // two doors — so whichever is open, the other shows it on its next load.
  function dl(id,list){
    return '<datalist id="'+id+'">'+(list||[]).map(function(v){
      return '<option value="'+esc(v)+'"></option>';}).join('')+'</datalist>';
  }
  function txt(k,i,v,ph,list){
    return '<input data-ial="'+k+'" data-i="'+i+'" value="'+esc(v||'')+'" placeholder="'+esc(ph||'')+'"'
      +(list?(' list="'+list+'"'):'')+' style="width:100%;min-width:110px;padding:4px;'
      +'border:1px solid #d1d5db;border-radius:6px;font-size:13px">';
  }
  function drawExtras(host){
    var P=D.extra_people||[], L=D.extra_locations||[], FILE=D.locations||[];
    var mine={}; L.forEach(function(l){mine[String(l.location||'').toLowerCase()]=1;});
    var fileRows=FILE.filter(function(l){return !mine[String(l.location||'').toLowerCase()];});
    var box=document.createElement('div');
    box.innerHTML=
      dl('ial-g1',D.group1_values)+dl('ial-g2',D.group2_values)
      +'<h3 style="margin:22px 0 4px;font-size:15px">Users added by hand</h3>'
      +'<p style="margin:0 0 8px;font-size:12px;color:#6b7280">People who are not in '
      +esc(D.users_dataset||'the users dataset')+'. Give them a group and the grants above reach '
      +'them like anybody else.</p>'
      +'<div class="ial-wrap"><table><thead><tr><th>Email</th><th>User</th><th>Group 1</th>'
      +'<th>Group 2</th><th>Access</th><th></th></tr></thead><tbody>'
      +(P.length?P.map(function(p,i){
        return '<tr>'
          +'<td>'+txt('pe',i,p.email,'name@company.com')+'</td>'
          +'<td>'+txt('pu',i,p.user,'81 - ALAMO')+'</td>'
          +'<td>'+txt('p1',i,p.group_1,'',"ial-g1")+'</td>'
          +'<td>'+txt('p2',i,p.group_2,'',"ial-g2")+'</td>'
          +'<td><select data-ial="pa" data-i="'+i+'">'
            +'<option value="member"'+(p.access!=='admin'?' selected':'')+'>Member</option>'
            +'<option value="admin"'+(p.access==='admin'?' selected':'')+'>Admin</option></select></td>'
          +'<td><button data-ial="pdrop" data-i="'+i+'">X</button></td></tr>';
        }).join('')
        :'<tr><td colspan="6" style="color:#6b7280">Nobody added by hand.</td></tr>')
      +'</tbody></table></div>'
      +'<div style="margin-top:8px"><button class="ial-add" data-ial="padd">+ Add a user</button></div>'
      ;
    host.appendChild(box);
  }
  function onChange(e){
    var el=e.target, k=el.getAttribute&&el.getAttribute('data-ial');
    if(!k||!D)return;
    if(k==='g1'||k==='g2'){ D.groups[k]=el.value; VALS={}; save(); return; }
    var PMAP={pe:'email',pu:'user',p1:'group_1',p2:'group_2',pa:'access'};
    var LMAP={};
    var j=parseInt(el.getAttribute('data-i'),10);
    if(PMAP[k]){ if(!isNaN(j)&&(D.extra_people||[])[j]){
      D.extra_people[j][PMAP[k]]=el.value; save(); } return; }
    if(LMAP[k]){ if(!isNaN(j)&&(D.extra_locations||[])[j]){
      D.extra_locations[j][LMAP[k]]=el.value; save(); } return; }
    var i=parseInt(el.getAttribute('data-i'),10);
    if(isNaN(i)||!D.grants[i])return;
    if(k==='vtick'){
      var cur=(D.grants[i].values||[]).map(String);
      if(el.checked){ if(cur.indexOf(el.value)<0)cur.push(el.value); }
      else cur=cur.filter(function(v){return v!==el.value;});
      D.grants[i].values=cur;
    } else if(k==='vexc'){
      D.grants[i].exclude=el.checked;
    } else if(k==='vfilter'){
      var q=(el.value||'').toLowerCase();
      el.parentElement.querySelectorAll('label').forEach(function(l){
        if(l.querySelector('[data-ial="vexc"]'))return;
        l.style.display=(!q||l.textContent.toLowerCase().indexOf(q)>=0)?'flex':'none';
      });
      return;
    } else if(k==='group1'||k==='group2'||k==='user'||k==='column'){
      D.grants[i][k]=el.value;
      if(k==='column')D.grants[i].values=[];
    } else return;
    save();
  }
  function onClick(e){
    var el=e.target, k=el.getAttribute&&el.getAttribute('data-ial');
    if(!k||!D)return;
    var di=parseInt(el.getAttribute('data-i'),10);
    if(k==='add'){ D.grants.push({group1:'',group2:'',user:'',column:'',values:[],exclude:false}); draw(); }
    else if(k==='drop'){
      var g=D.grants[di]||{};
      var who=[].concat(g.user||[],g.group2||[],g.group1||[]).filter(Boolean).join(', ')||'everyone in this app';
      if(!confirm('Delete this grant?\n\n'+who+'\n\nThey lose this access the moment it is gone.'))return;
      D.grants.splice(di,1); save();
    }
    else if(k==='vall'){ var g2=D.grants[di];
      if(g2&&g2.column){ vals(D.catalog_dataset,g2.column).then(function(v){
        g2.values=(v||[]).map(String); save(); }); } }
    else if(k==='vnone'){ if(D.grants[di]){ D.grants[di].values=[]; save(); } }
    else if(k==='padd'){ D.extra_people=(D.extra_people||[]).concat(
        [{email:'',user:'',group_1:'',group_2:'',access:'member'}]); draw(); }
    else if(k==='pdrop'){
      var pe=(D.extra_people[di]||{}).email||'this person';
      if(!confirm('Remove '+pe+' from the hand-added users?'))return;
      D.extra_people.splice(di,1); save();
    }

  }
  function load(){
    return fetch('/api/admin/app-users',{credentials:'same-origin'})
      .then(function(r){return r.ok?r.json():null;})
      .then(function(j){ if(!j)return; D=j; D.groups=D.groups||{g1:'',g2:''}; D.grants=D.grants||[];
        D.extra_people=D.extra_people||[]; D.extra_locations=D.extra_locations||[]; draw(); })
      .catch(function(){});
  }
  function leaves(re){
    var out=[], all=document.querySelectorAll('body *');
    for(var i=0;i<all.length;i++){
      var el=all[i];
      if(el.children.length)continue;
      var t=(el.textContent||'').replace(/\s+/g,' ').trim();
      if(re.test(t))out.push(el);
    }
    return out;
  }
  function relabel(){
    leaves(/^people\s*&\s*passwords$/i).forEach(function(el){ el.textContent='Passwords'; });
    var ps=document.querySelectorAll('p');
    for(var j=0;j<ps.length;j++){
      if(ps[j].children.length)continue;
      var s=ps[j].textContent||'';
      if(/rows of the location dataset/i.test(s)){
        ps[j].textContent=s.replace(/rows of the location dataset your catalog covers/i,
          'people in the users dataset this catalog serves');
      }
    }
  }
  // The Role column used to be decided by WHICH email column named you. In
  // the shape everyone is built to now there is one address column, so that
  // question has one answer for everybody and the whole list read "Purchasing
  // Director". Group 1 is what actually says what someone is, so it is what
  // the column shows — sourced from the same list the table is drawn from.
  var GROUPS=null;
  function humanGroup(s){
    return String(s||'').split('_').filter(Boolean)
      .map(function(w){return w.charAt(0).toUpperCase()+w.slice(1).toLowerCase();}).join(' ');
  }
  function paintRoles(){
    if(!GROUPS)return;
    var rows=document.querySelectorAll('tr');
    for(var i=0;i<rows.length;i++){
      var cells=rows[i].cells; if(!cells||cells.length<2)continue;
      var em=(cells[0].textContent||'').trim().toLowerCase();
      if(em.indexOf('@')<1)continue;
      var g=GROUPS[em];
      if(g&&(cells[1].textContent||'').trim()!==humanGroup(g))cells[1].textContent=humanGroup(g);
    }
  }
  function loadRoles(){
    return fetch('/api/admin/my-people',{credentials:'same-origin'})
      .then(function(r){return r.ok?r.json():null;})
      .then(function(j){
        if(!j||!j.people)return;
        GROUPS={};
        j.people.forEach(function(p){ if(p.group)GROUPS[String(p.email).toLowerCase()]=p.group; });
        paintRoles();
      }).catch(function(){});
  }
  function mount(){
    relabel();
    loadRoles();
    if(document.getElementById('ial-users'))return;
    var anchor=null, hs=document.querySelectorAll('h1,h2,h3,h4');
    for(var i=0;i<hs.length;i++){
      var t=(hs[i].textContent||'').trim();
      if(/^users$/i.test(t)){anchor=hs[i];break;}
    }
    if(!anchor)for(var j=0;j<hs.length;j++){
      var t2=(hs[j].textContent||'').trim();
      if(/^locations$/i.test(t2)){anchor=hs[j];break;}
    }
    var box=document.createElement('div');
    box.id='ial-users';
    box.innerHTML='<div style="color:#6b7280">Loading...</div>';
    if(anchor&&anchor.parentNode)anchor.parentNode.insertBefore(box,anchor.nextSibling);
    else document.body.appendChild(box);
    document.addEventListener('change',onChange,true);
    document.addEventListener('click',onClick,true);
    load();
  }
  if(document.readyState!=='loading')mount(); else document.addEventListener('DOMContentLoaded',mount);
  if(window.MutationObserver)new MutationObserver(function(){relabel();paintRoles();})
    .observe(document.documentElement,{childList:true,subtree:true});
})();
</script>
""".encode("utf-8")


def _with_users_panel(body: bytes) -> bytes:
    if b'id="cat-users-panel"' in body:
        return body
    cut = body.lower().rfind(b"</body>")
    if cut == -1:
        return body + USERS_PANEL
    return body[:cut] + USERS_PANEL + body[cut:]


HUMANIZE_SNIPPET = b"""
<script id="cat-humanize">
(function(){
  var SPECIAL={id:'ID',url:'URL',sku:'SKU',upc:'UPC',qty:'Qty',ai:'AI'};
  function human(s){
    return s.split('_').filter(Boolean).map(function(w){
      var lw=w.toLowerCase();
      return SPECIAL[lw]||lw.charAt(0).toUpperCase()+lw.slice(1);
    }).join(' ');
  }
  var RAW=/^[a-z][a-z0-9]*(_[a-z0-9]+)+$/;
  var WORD=/^[a-z][a-z0-9]{2,}$/;
  var busy=false;
  function fix(){
    if(busy)return; busy=true;
    try{
      document.querySelectorAll('th').forEach(function(el){
        if(el.childElementCount)return;
        var t=el.textContent.trim();
        if(RAW.test(t)||WORD.test(t))el.textContent=human(t);
      });
      document.querySelectorAll('p,div,span,label,option').forEach(function(el){
        if(el.childElementCount)return;
        var t=el.textContent;
        if(t.indexOf('_')<0)return;
        el.textContent=t.replace(/\\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\\b/g,human);
      });
    }finally{setTimeout(function(){busy=false;},250);}
  }
  window.addEventListener('load',fix);
  document.addEventListener('DOMContentLoaded',fix);
  if(window.MutationObserver)new MutationObserver(function(){fix();})
    .observe(document.documentElement,{childList:true,subtree:true});
})();
</script>
"""


def _with_humanizer(body: bytes) -> bytes:
    if b'id="cat-humanize"' in body:
        return body
    cut = body.lower().rfind(b"</body>")
    if cut == -1:
        return body + HUMANIZE_SNIPPET
    return body[:cut] + HUMANIZE_SNIPPET + body[cut:]


@app.get("/admin")
async def admin_page():
    try:
        with open("static/admin.html", "rb") as fh:
            return Response(_with_users_panel(_with_humanizer(_with_admin_guide(fh.read()))),
                            media_type="text/html",
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
    if request is None or not request.cookies.get(SESSION_COOKIE):
        return {}
    try:
        who = await _whoami(request)
    except Exception:
        return {}
    return (who or {}).get("scope") or {} if who else {}


def _scope_administers(sc: dict) -> bool:
    return sc.get("all") is True or str(sc.get("role") or "") in ("owner", "admin")


async def _may_administer(request) -> bool:
    return _scope_administers(await _me_scope(request))


BUDGET_LINE_BLOCK = b"""
<script>(function(){
 var B=null;
 function money(n){return '$'+(+n).toLocaleString(undefined,{maximumFractionDigits:0});}
 function cartTotal(){ var el=document.getElementById('orderTotal'); if(!el) return 0;
   var n=parseFloat(String(el.textContent||'').replace(/[^0-9.\-]/g,'')); return isNaN(n)?0:n; }
 function draw(){ if(!B||!B.length) return;
   var fm=document.getElementById('freightMin'); if(!fm||!fm.parentNode) return;
   var el=document.getElementById('budgetLine');
   if(!el){ el=document.createElement('div'); el.id='budgetLine';
     el.style.cssText='text-align:left;margin:6px 0;font-size:0.9rem;font-weight:bold;';
     fm.parentNode.insertBefore(el, fm.nextSibling); }
   var t=cartTotal();
   el.innerHTML=B.map(function(b){
     var after=b.spent+t; var over=after>b.budget;
     return '<div style="color:'+(over?'#e53935':'#12925f')+'">Budget \u2014 '+b.name+': '+
       money(b.spent)+' spent of '+money(b.budget)+
       (t?' \u00b7 with this order: '+money(after):'')+
       (over?' \u2014 OVER BUDGET (admin approval needed)':' \u2014 ok')+'</div>';
   }).join('');
 }
 function load(){ fetch('/api/app/my-budget',{credentials:'same-origin'})
   .then(function(r){return r.ok?r.json():null;})
   .then(function(d){ B=(d&&d.budgets)||[]; draw(); }).catch(function(){}); }
 load(); setInterval(load, 90000); setInterval(draw, 1200);
})();</script>
"""


def _tabs_block(sc: dict) -> bytes:
    """Hide the tabs this person may not reach — decided by the server, baked
    into the page as literal values, no extra request from the browser."""
    pr = dict(_PERM_DEFAULT)
    pr.update(_clean_perms((sc or {}).get("perms") or {}))
    allowed = []
    if pr.get("catalog", True):
        allowed.append("catalog")
    if pr.get("order", True):
        allowed.append("order")
    if _PENDING_LEVELS.get(str(pr.get("pending", "delete")).lower(), 3) >= 1:
        allowed.append("pending")
    if len(allowed) >= 3:
        return b""
    js = ("<script>(function(){var A=" + json.dumps(allowed) + ";"
          "function fix(){['__dtabs','__mtabs'].forEach(function(id){"
          "var bar=document.getElementById(id);if(!bar)return;"
          "bar.querySelectorAll('button[data-v]').forEach(function(b){"
          "if(A.indexOf(b.getAttribute('data-v'))<0)b.style.display='none';});});}"
          "var n=0;var t=setInterval(function(){fix();if(++n>25)clearInterval(t);},400);"
          "setTimeout(function(){try{if(window.__showView&&A.length&&A.indexOf('catalog')<0)"
          "window.__showView(A[0]);}catch(e){}},2600);"
          "})();</script>")
    return js.encode()


def _with_admin_launcher(body: bytes, may_administer: bool = False, sc: dict | None = None) -> bytes:
    """Pin Sign out for everybody; add the Admin button only where it belongs;
    trim the tab bar to what this person may reach."""
    if b'id="cat-signout-css"' in body:
        return body
    block = SIGNOUT_BLOCK + _tabs_block(sc or {}) + (ADMIN_BUTTON if may_administer else b"")
    if sc and not sc.get("all") and "perms" in sc:
        block += BUDGET_LINE_BLOCK
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
    return Response(_with_admin_launcher(body, _scope_administers(sc), sc),
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



# ---------------- users & access, mirrored from ETL Space ----------------
#
# The Admin page here and the Apps tab in ETL Space are two windows on one
# thing. Rather than a second implementation drifting away from the first,
# both ask ETL the same question; this is only the pass-through.

@app.get("/api/admin/app-users")
async def admin_app_users(request: Request):
    return await etl_get("/api/access/app-users", request=request)


@app.post("/api/admin/app-users")
async def admin_save_app_users(request: Request):
    body = await request.json()
    return await etl_send("POST", "/api/access/app-users", body, request=request)


@app.get("/api/admin/app-values")
async def admin_app_values(dataset: str, column: str, request: Request):
    return await etl_get("/api/access/app-values",
                         {"dataset": dataset, "column": column}, request=request)


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


# NOTE: the static-file mount used to live here.  It now sits at the very
# BOTTOM of this file — routes are matched in the order they are defined, and
# a mount at "/" catches every path, so anything defined after it (like the
# Builder endpoints below) would be unreachable.  Keep the mount last, always.


# ════════════════════════════════════════════════════════════════════════════
# THE CATALOG BUILDER — this app's own ETL, on this app's own database.
#
# The catalog used to be built in ETL Space and served from its store. This
# section is the start of standing alone: vendor files are uploaded HERE,
# checked against the catalog's own schema HERE, appended into one catalog
# HERE, and served from a database that belongs to this app. ETL Space keeps
# sign-in and the mapping app; the catalog's data world lives at home now.
#
# Three moves, deliberately simpler than the tool this replaces:
#   1. CONNECT   — drop a vendor file in; it becomes a source.
#   2. CHECK     — every source is read against the schema the catalog needs;
#                  what can be recognised is mapped by itself, the rest is a
#                  dropdown, and nothing builds while a required field is dark.
#   3. BUILD     — every ready source is normalised to the schema and appended
#                  into one catalog dataset, which the storefront serves at
#                  once, from here.
# ════════════════════════════════════════════════════════════════════════════

_BDB = {"engine": None}


def _builder_engine():
    url = os.environ.get("CATALOG_DATABASE_URL", "").strip()
    if not url:
        raise HTTPException(400, "The catalog's own database is not connected yet. In Render, "
                                 "copy catalog-db's Internal Database URL into this service as "
                                 "CATALOG_DATABASE_URL, and this screen comes alive.")
    if _BDB["engine"] is None:
        from sqlalchemy import create_engine
        _BDB["engine"] = create_engine(url, pool_pre_ping=True, pool_size=3, max_overflow=2)
        _builder_migrate(_BDB["engine"])
    return _BDB["engine"]


def _builder_migrate(engine):
    """Create and upgrade the store. Every statement runs in its OWN
    transaction: on Postgres one failed statement poisons a shared
    transaction, and on a brand-new database that used to mean no tables
    were created at all."""
    from sqlalchemy import text
    statements = [
        """create table if not exists cat_sources(
                id text primary key,
                customer text not null,
                name text not null,
                filename text default '',
                vendor_label text default '',
                table_name text not null,
                mapping text default '{}',
                row_count integer default 0,
                added_at timestamp default current_timestamp,
                updated_at timestamp default current_timestamp)""",
        """create table if not exists cat_built(
                customer text primary key,
                table_name text not null,
                row_count integer default 0,
                serving boolean default true,
                built_at timestamp default current_timestamp)""",
        """create table if not exists cat_people(
                email text primary key,
                customer text not null default '',
                user_label text default '',
                group1 text default '',
                group2 text default '',
                admin boolean default false,
                vendors_mode text default 'all',
                vendors text default '[]',
                pw_hash text default '',
                must_change boolean default false,
                added_at timestamp default current_timestamp,
                last_signin text default '',
                perms text default '{}',
                budget text default '')""",
        """create table if not exists cat_kv(
                k text primary key,
                v text default '')""",
        """create table if not exists cat_orders(
                id text primary key,
                coll text not null default '',
                customer text not null default '',
                content text not null default '{}',
                created_at timestamp default current_timestamp,
                updated_at timestamp default current_timestamp)""",
        """create table if not exists cat_groups(
                customer text not null default '',
                name text not null,
                parent text default '',
                vendors_mode text default 'all',
                vendors text default '[]',
                perms text default '{}',
                budget text default '',
                primary key (customer, name))""",
        """create table if not exists cat_vendorinfo(
                customer text not null default '',
                vendor text not null,
                order_email text default '',
                freight_min text default '',
                freight_min_by_cat text default '',
                freight_min_by_brand text default '',
                freight_qty_or_cost text default '',
                primary key (customer, vendor))""",
        # upgrades for stores created before these columns existed
        "alter table cat_sources add column if not exists feed text default '{}'",
        "alter table cat_sources add column if not exists feed_status text default '{}'",
        "alter table cat_people add column if not exists perms text default '{}'",
        "alter table cat_people add column if not exists budget text default ''",
        "alter table cat_groups add column if not exists perms text default '{}'",
        "alter table cat_groups add column if not exists budget text default ''",
    ]
    for ddl in statements:
        try:
            with engine.begin() as c:
                c.execute(text(ddl))
        except Exception:
            pass


# The schema the catalog reads — the same names the storefront asks for.
BUILDER_FIELDS = [
    ("ModelNum",     True,  "Model / SKU the order is placed against"),
    ("ItemName",     True,  "Product name on the card"),
    ("Vendor",       True,  "Who supplies it — filled from the label below if the file has no column"),
    ("RegularCost",  True,  "List cost"),
    ("Price",        False, "Promotional cost, where there is one"),
    ("ItemImage2",   False, "Image URL the card shows"),
    ("Brand",        False, ""), ("Category", False, ""), ("SubCategory", False, ""),
    ("Collection",   False, ""), ("Color", False, ""),
    ("DisplayOrder", False, "Sort order"), ("QtyAvailable", False, "Stock on hand"),
]
_BUILDER_ALIASES = {
    "ModelNum": ["model", "model_num", "modelnum", "model_number", "model #", "sku", "item_number"],
    "ItemName": ["item_name", "itemname", "description", "item_description",
                 "product_name", "title", "item", "name"],
    "Vendor": ["vendor", "vendor_name", "supplier"],
    "Brand": ["brand"], "Category": ["category"],
    "SubCategory": ["sub_category", "subcategory", "sub category"],
    "Collection": ["collection"],
    "RegularCost": ["regular_cost", "regularcost", "regular cost", "cost", "price"],
    "Price": ["promo_cost", "promocost", "promo cost", "sale_price", "price"],
    "Color": ["color", "colour"],
    "ItemImage2": ["item_image_2", "item_image", "item_display_image_1", "image", "image_url",
                   "item_image_jpeg"],
    "DisplayOrder": ["display_order", "displayorder", "display order"],
    "QtyAvailable": ["qty_available", "qtyavailable", "qty available", "quantity", "stock"],
}


def _bnorm(s: str) -> str:
    return "".join(ch for ch in str(s).lower() if ch.isalnum())


def _builder_automap(columns) -> dict:
    """Which column supplies each schema field — recognised, never invented."""
    by_norm = {}
    for c in columns:
        by_norm.setdefault(_bnorm(c), str(c))
    out = {}
    for name, _req, _h in BUILDER_FIELDS:
        hit = by_norm.get(_bnorm(name))
        if not hit:
            for cand in _BUILDER_ALIASES.get(name, []):
                hit = by_norm.get(_bnorm(cand))
                if hit:
                    break
        if hit:
            out[name] = hit
    return out


def _bslug(s: str) -> str:
    out = "".join(ch if ch.isalnum() else "_" for ch in str(s).lower()).strip("_")
    while "__" in out:
        out = out.replace("__", "_")
    return out or "x"


def _builder_only_customer() -> str:
    """When the ETL no longer says which customer this is — its catalog app was
    deleted, say — but this app's own store holds exactly one customer's
    catalog, that one is the answer. The catalog outlives the ETL tie."""
    try:
        from sqlalchemy import text
        eng = _builder_engine()
        with eng.connect() as c:
            custs = {r[0] for r in c.execute(text("select distinct customer from cat_sources"))}
            custs |= {r[0] for r in c.execute(text("select distinct customer from cat_built"))}
        custs = {c for c in custs if c}
        if len(custs) == 1:
            return next(iter(custs))
        if len(custs) > 1:
            # Several lives of this catalog linger (old demo keys from before a
            # cleanup). The one built most recently is the live one.
            with eng.connect() as c:
                row = c.execute(text("select customer from cat_built "
                                     "order by built_at desc limit 1")).first()
                if row and row[0]:
                    return row[0]
                row = c.execute(text("select customer from cat_sources "
                                     "order by added_at desc limit 1")).first()
                if row and row[0]:
                    return row[0]
    except Exception:
        pass
    return ""


async def _builder_admin(request: Request):
    """Who is asking, and which customer's builder is this — answered by this
    app's own people first, the ETL session only as the transition fallback."""
    who = await _whoami(request)
    if who is None:
        raise HTTPException(401, "Not signed in.")
    if not who["admin"]:
        raise HTTPException(403, "Only an administrator or the catalog owner can build the catalog.")
    sc = who["scope"] or {}
    customer = str(sc.get("customer") or "").strip()
    if not customer and not who.get("local"):
        try:
            my = await _my_datasets(request)
            customer = str((my or {}).get("customer") or "").strip()
        except Exception:
            customer = ""
    if not customer:
        only = _builder_only_customer()
        if only:
            return sc, only, only
        customer = os.environ.get("CATALOG_CUSTOMER", "").strip() or "main"
    return sc, _bslug(customer), customer


def _builder_missing(mapping: dict, vendor_label: str) -> list:
    out = []
    for name, req, _h in BUILDER_FIELDS:
        if not req:
            continue
        if name == "Vendor" and (mapping.get("Vendor") or vendor_label):
            continue
        if not mapping.get(name):
            out.append(name)
    return out


@app.get("/api/admin/builder")
async def builder_state(request: Request):
    sc, cust, label = await _builder_admin(request)
    if not os.environ.get("CATALOG_DATABASE_URL", "").strip():
        return {"connected": False, "customer": label,
                "fields": [{"name": n, "required": r, "help": h} for n, r, h in BUILDER_FIELDS],
                "sources": [], "built": None}
    from sqlalchemy import text
    eng = _builder_engine()
    with eng.connect() as c:
        rows = c.execute(text("select * from cat_sources where customer=:c "
                              "order by added_at desc"),
                         {"c": cust}).mappings().all()
        built = c.execute(text("select * from cat_built where customer=:c"),
                          {"c": cust}).mappings().first()
    sources = []
    for r in rows:
        m = json.loads(r["mapping"] or "{}")
        try:
            from sqlalchemy import inspect as _inspect
            cols = [col["name"] for col in _inspect(eng).get_columns(r["table_name"])]
        except Exception:
            cols = []
        sources.append({"id": r["id"], "name": r["name"], "filename": r["filename"],
                        "pending": (int(r["row_count"] or 0) == 0
                                    and not str(r["filename"] or "").strip()),
                        "vendor": r["vendor_label"], "rows": r["row_count"],
                        "mapping": m, "columns": cols,
                        "missing": _builder_missing(m, r["vendor_label"]),
                        "feed": _feed_public(_feed_of(r)),
                        "feed_addr": _feed_address(str(r["id"])),
                        "feed_status": _feed_status_of(r)})
    host, _p, user, pw = _email_env()
    return {"connected": True, "customer": label,
            "fields": [{"name": n, "required": r, "help": h} for n, r, h in BUILDER_FIELDS],
            "sources": sources,
            "email_ready": bool(host and user and pw),
            "built": ({"rows": built["row_count"], "at": str(built["built_at"])[:19],
                       "serving": bool(built["serving"])} if built else None)}


@app.post("/api/admin/builder/create")
async def builder_create(request: Request):
    """A source with no file yet — its feed (API, SFTP or email) brings the
    first one. Until then it waits, and builds skip it."""
    sc, cust, _label = await _builder_admin(request)
    body = await request.json() or {}
    name = str(body.get("name") or "").strip()[:80]
    if not name:
        raise HTTPException(400, "Give the source a name — usually the vendor's.")
    vendor = str(body.get("vendor") or name).strip()[:80]
    eng = _builder_engine()
    sid = secrets.token_hex(4)
    from sqlalchemy import text
    with eng.begin() as c:
        c.execute(text("insert into cat_sources(id,customer,name,filename,vendor_label,"
                       "table_name,mapping,row_count) values(:i,:c,:n,'',:v,:t,'{}',0)"),
                  {"i": sid, "c": cust, "n": name, "v": vendor, "t": f"src_{cust}_{sid}"})
    return {"ok": True, "id": sid,
            "message": f"{name} created. Set its feed on the card and press Check now — "
                       f"the first file it pulls fills the source."}


@app.post("/api/admin/builder/upload")
async def builder_upload(request: Request):
    sc, cust, _label = await _builder_admin(request)
    body = await request.json()
    filename = str((body or {}).get("filename") or "upload.csv")
    vendor = str((body or {}).get("vendor") or "").strip()
    raw = base64.b64decode(str((body or {}).get("content_b64") or ""), validate=False)
    try:
        df = _builder_read_frame(filename, raw)
    except ValueError as e:
        raise HTTPException(400, str(e))
    eng = _builder_engine()
    sid = secrets.token_hex(4)
    table = f"src_{cust}_{sid}"
    df.astype(str).to_sql(table, eng, if_exists="replace", index=False, chunksize=2000)
    mapping = _builder_automap(df.columns)
    from sqlalchemy import text
    with eng.begin() as c:
        c.execute(text("insert into cat_sources(id,customer,name,filename,vendor_label,"
                       "table_name,mapping,row_count) values(:i,:c,:n,:f,:v,:t,:m,:r)"),
                  {"i": sid, "c": cust, "n": filename.rsplit(".", 1)[0][:80], "f": filename[:120],
                   "v": vendor[:80], "t": table, "m": json.dumps(mapping), "r": int(len(df))})
    return {"ok": True, "id": sid, "rows": int(len(df)),
            "mapped": len(mapping), "missing": _builder_missing(mapping, vendor)}


@app.post("/api/admin/builder/map")
async def builder_map(request: Request):
    sc, cust, _label = await _builder_admin(request)
    body = await request.json()
    sid = str((body or {}).get("id") or "")
    from sqlalchemy import text
    eng = _builder_engine()
    with eng.begin() as c:
        row = c.execute(text("select * from cat_sources where id=:i and customer=:c"),
                        {"i": sid, "c": cust}).mappings().first()
        if not row:
            raise HTTPException(404, "No such source.")
        vals = {}
        if "mapping" in (body or {}):
            m = {str(k): str(v) for k, v in ((body or {}).get("mapping") or {}).items() if str(v)}
            vals["mapping"] = json.dumps(m)
        if "vendor" in (body or {}):
            vals["vendor_label"] = str((body or {}).get("vendor") or "")[:80]
        if vals:
            sets = ", ".join(f"{k}=:{k}" for k in vals)
            vals.update({"i": sid, "c": cust})
            c.execute(text(f"update cat_sources set {sets}, updated_at=now() "
                           "where id=:i and customer=:c"), vals)
    return {"ok": True}


@app.post("/api/admin/builder/remove")
async def builder_remove(request: Request):
    sc, cust, _label = await _builder_admin(request)
    body = await request.json()
    sid = str((body or {}).get("id") or "")
    from sqlalchemy import text
    eng = _builder_engine()
    with eng.begin() as c:
        row = c.execute(text("select table_name from cat_sources where id=:i and customer=:c"),
                        {"i": sid, "c": cust}).mappings().first()
        if not row:
            raise HTTPException(404, "No such source.")
        c.execute(text("delete from cat_sources where id=:i and customer=:c"),
                  {"i": sid, "c": cust})
        c.execute(text(f'drop table if exists "{row["table_name"]}"'))
    return {"ok": True}


@app.get("/api/admin/builder/preview")
async def builder_preview(request: Request, id: str = ""):
    """The first rows of one source AS THE CATALOG WILL SEE THEM."""
    sc, cust, _label = await _builder_admin(request)
    import pandas as pd
    from sqlalchemy import text
    eng = _builder_engine()
    with eng.connect() as c:
        row = c.execute(text("select * from cat_sources where id=:i and customer=:c"),
                        {"i": id, "c": cust}).mappings().first()
    if not row:
        raise HTTPException(404, "No such source.")
    df = pd.read_sql_query(f'select * from "{row["table_name"]}" limit 8', eng)
    m = json.loads(row["mapping"] or "{}")
    out = pd.DataFrame()
    for name, _req, _h in BUILDER_FIELDS:
        src = m.get(name)
        if src and src in df.columns:
            out[name] = df[src].astype(str)
        elif name == "Vendor" and row["vendor_label"]:
            out[name] = row["vendor_label"]
        else:
            out[name] = ""
    return {"columns": list(out.columns), "rows": json.loads(out.to_json(orient="records"))}


def _builder_do_build(eng, cust: str):
    """Append every ready source into one catalog table. Raises ValueError with
    a human sentence when it cannot. Keeps the current serving switch."""
    import pandas as pd
    from sqlalchemy import text
    with eng.connect() as c:
        srcs = c.execute(text("select * from cat_sources where customer=:c order by added_at"),
                         {"c": cust}).mappings().all()
    if not srcs:
        raise ValueError("No sources yet — upload at least one vendor file first.")
    srcs = [r for r in srcs
            if int(r["row_count"] or 0) > 0 or str(r["filename"] or "").strip()]
    if not srcs:
        raise ValueError("Every source is still waiting for its feed's first pull — "
                         "press Check now on a card, or upload a file.")
    blocked = []
    for r in srcs:
        miss = _builder_missing(json.loads(r["mapping"] or "{}"), r["vendor_label"])
        if miss:
            blocked.append(f"{r['name']}: {', '.join(miss)}")
    if blocked:
        raise ValueError("Not built — these sources still have required fields with no "
                         "column: " + " · ".join(blocked[:4]))
    frames, per = [], []
    for r in srcs:
        df = pd.read_sql_table(r["table_name"], eng)
        m = json.loads(r["mapping"] or "{}")
        out = pd.DataFrame()
        for name, _req, _h in BUILDER_FIELDS:
            src = m.get(name)
            if src and src in df.columns:
                out[name] = df[src].astype(str)
            elif name == "Vendor" and r["vendor_label"]:
                out[name] = r["vendor_label"]
            else:
                out[name] = ""
        out = out[out["ModelNum"].astype(str).str.strip() != ""]
        frames.append(out)
        per.append({"source": r["name"], "rows": int(len(out))})
    allf = pd.concat(frames, ignore_index=True)
    table = f"built_{cust}"
    allf.to_sql(table, eng, if_exists="replace", index=False, chunksize=2000)
    with eng.begin() as c:
        c.execute(text("delete from cat_built where customer=:c"), {"c": cust})
        c.execute(text("insert into cat_built(customer,table_name,row_count,serving) "
                       "values(:c,:t,:r,true)"), {"c": cust, "t": table, "r": int(len(allf))})
    return int(len(allf)), per


@app.post("/api/admin/builder/build")
async def builder_build(request: Request):
    sc, cust, _label = await _builder_admin(request)
    eng = _builder_engine()
    try:
        total, per = await asyncio.to_thread(_builder_do_build, eng, cust)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "rows": total, "sources": per,
            "message": f"Built {total} rows from {len(per)} source"
                       f"{'' if len(per) == 1 else 's'}. The catalog is serving it now."}


# (The serve/stop-serving switch is gone on purpose: once a catalog is built it
#  IS the catalog. The serving column stays in the schema, always true.)


# ── serving: the storefront reads the built catalog from HERE when one exists ──

_BSCOPE: dict = {}


async def _builder_rows_local(ident: str, request: Request):
    """Serve catalog rows from this app's own store, when this customer has
    built one and left it serving. Anything else returns None and the request
    proxies exactly as before — including every other role the page reads."""
    try:
        if _role_of(ident) != "catalog":
            return None
        if not os.environ.get("CATALOG_DATABASE_URL", "").strip():
            return None
        tok = request.cookies.get(SESSION_COOKIE, "")
        if not tok:
            return None
        now = time.time()
        hit = _BSCOPE.get(tok)
        if hit and hit[0] > now:
            sc = hit[1]
        else:
            who = await _whoami(request)
            if who is None:
                return None
            sc = who["scope"] or {}
            _BSCOPE[tok] = (now + 60, sc)
            if len(_BSCOPE) > 500:
                for k in [k for k, v in list(_BSCOPE.items()) if v[0] <= now]:
                    _BSCOPE.pop(k, None)
        if not (sc.get("perms") or _PERM_DEFAULT).get("catalog", True):
            return JSONResponse([])          # no Catalog tab for this person
        cust = _bslug(str(sc.get("customer") or "")) if str(sc.get("customer") or "").strip() else ""
        if not cust or cust == "x":
            cust = _builder_only_customer()
        if not cust:
            return None
        import pandas as pd
        from sqlalchemy import text
        eng = _builder_engine()
        with eng.connect() as c:
            built = c.execute(text("select * from cat_built where customer=:c and serving"),
                              {"c": cust}).mappings().first()
        if not built:
            return None
        df = pd.read_sql_table(built["table_name"], eng)
        # Access still means something here: a person whose reach is a set of
        # vendors sees exactly those vendors of the built catalog — and "all
        # except these" stays durable as new vendors arrive.
        if not sc.get("all") and not sc.get("vendors_all"):
            vend = {str(v).strip().lower() for v in (sc.get("vendors") or [])}
            col = df["Vendor"].astype(str).str.strip().str.lower()
            if str(sc.get("vendors_mode") or "") == "except":
                df = df[~col.isin(vend)] if vend else df
            else:
                df = df[col.isin(vend)] if vend else df.iloc[0:0]
        params = dict(request.query_params)
        want = [c.strip() for c in (params.get("groupby") or params.get("fields") or "").split(",")
                if c.strip()]
        if want:
            by_norm = {}
            for c in df.columns:
                by_norm.setdefault(_bnorm(c), c)
            have = [by_norm[_bnorm(w)] for w in want if _bnorm(w) in by_norm]
            have = list(dict.fromkeys(have))
            if have:
                df = df[have]
                if params.get("groupby"):
                    df = df.drop_duplicates()
        try:
            lim = max(1, min(int(params.get("limit") or 100000), 500000))
        except Exception:
            lim = 100000
        df = df.head(lim)
        return JSONResponse(json.loads(df.to_json(orient="records")))
    except HTTPException:
        return None
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════════════════
# THE PEOPLE OF THIS CATALOG — standalone sign-in, users, passwords, reach.
#
# This is the detachment from the ETL. People are rows in this app's own
# database, added one at a time in the admin. The same row feeds three things:
#   sign-in    — email + password (hashed here, checked here, session minted here)
#   grants     — group 1, group 2, user label, and which vendors they reach
#   passwords  — the Passwords tab manages the hash on this row
# While ETL_BASE_URL is still set, an email with no local row falls back to the
# ETL, so nothing breaks mid-move. Remove that variable and the app stands alone.
# ════════════════════════════════════════════════════════════════════════════

def _people_on() -> bool:
    return bool(os.environ.get("CATALOG_DATABASE_URL", "").strip())


def _local_secret() -> bytes:
    s = os.environ.get("SESSION_SECRET", "").strip()
    if s:
        return s.encode()
    from sqlalchemy import text
    eng = _builder_engine()
    with eng.begin() as c:
        row = c.execute(text("select v from cat_kv where k='session_secret'")).first()
        if row and row[0]:
            return str(row[0]).encode()
        v = secrets.token_hex(32)
        c.execute(text("insert into cat_kv(k,v) values('session_secret',:v)"), {"v": v})
        return v.encode()


def _local_token(email: str) -> str:
    hours = int(os.environ.get("SESSION_HOURS", "12") or 12)
    msg = f"{email.strip().lower()}|{int(time.time()) + hours * 3600}"
    sig = hmac.new(_local_secret(), msg.encode(), hashlib.sha256).hexdigest()
    # no '=' padding — an '=' in a cookie value gets the whole cookie quoted
    return "v1." + base64.urlsafe_b64encode(msg.encode()).decode().rstrip("=") + "." + sig


def _local_token_email(tok: str) -> str:
    try:
        tok = tok.strip('"')          # some clients hand a quoted cookie back
        _v, b64, sig = tok.split(".", 2)
        msg = base64.urlsafe_b64decode((b64 + "=" * (-len(b64) % 4)).encode()).decode()
        if not hmac.compare_digest(
                hmac.new(_local_secret(), msg.encode(), hashlib.sha256).hexdigest(), sig):
            return ""
        email, exp = msg.rsplit("|", 1)
        if time.time() > float(exp):
            return ""
        return email
    except Exception:
        return ""


def _pw_make(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000).hex()
    return f"pbkdf2${salt}${h}"


def _pw_check(pw: str, stored: str) -> bool:
    try:
        _alg, salt, h = stored.split("$", 2)
        cand = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000).hex()
        return hmac.compare_digest(cand, h)
    except Exception:
        return False


def _person(email: str):
    if not _people_on():
        return None
    from sqlalchemy import text
    try:
        with _builder_engine().connect() as c:
            return c.execute(text("select * from cat_people where email=:e"),
                             {"e": str(email).strip().lower()}).mappings().first()
    except Exception:
        return None


# What a person may reach in the storefront: the Catalog tab, the Order Form,
# and Pending orders (none / read / write / delete-anything). Nothing set
# anywhere means everything — you limit by setting less on a group or a person.
_PERM_DEFAULT = {"catalog": True, "order": True, "pending": "delete"}
_PENDING_LEVELS = {"none": 0, "read": 1, "write": 2, "delete": 3}


def _clean_perms(d) -> dict:
    out = {}
    if not isinstance(d, dict):
        return out
    for k in ("catalog", "order"):
        v = d.get(k)
        if isinstance(v, bool):
            out[k] = v
        elif str(v).strip().lower() in ("yes", "true", "1"):
            out[k] = True
        elif str(v).strip().lower() in ("no", "false", "0"):
            out[k] = False
    v = str(d.get("pending") or "").strip().lower()
    if v in _PENDING_LEVELS:
        out["pending"] = v
    return out


def _pending_level(sc: dict) -> int:
    pr = (sc or {}).get("perms") or {}
    return _PENDING_LEVELS.get(str(pr.get("pending", "delete")).lower(), 3)


def _money(s):
    try:
        v = float(str(s).replace("$", "").replace(",", "").strip())
        return v if v > 0 else None
    except Exception:
        return None


def _person_group_names(cust: str, g2: str, g1: str) -> set:
    """Every group this person is in, parents included — the cascade."""
    names = set()
    for gname in (str(g2 or "").strip(), str(g1 or "").strip()):
        seen = set()
        g = _group_row(cust, gname)
        while g is not None and g["name"] not in seen and len(seen) < 12:
            seen.add(g["name"])
            names.add(g["name"])
            g = _group_row(cust, str(g["parent"] or "").strip())
    return names


def _month_spend(eng, cust: str, exclude_order: str = "") -> dict:
    """This month's ordered total per submitter email. Deleted lines and the
    order currently being submitted are left out."""
    from sqlalchemy import text
    month = time.strftime("%Y-%m")
    out = {}
    with eng.connect() as c:
        rows = c.execute(text("select content, created_at from cat_orders where customer=:c"),
                         {"c": cust}).all()
    for content, created in rows:
        try:
            d = json.loads(content or "{}")
        except Exception:
            continue
        if d.get("_deleted"):
            continue
        if exclude_order and str(d.get("OrderNumber") or "") == exclude_order:
            continue
        if str(created or "")[:7] != month:
            continue
        try:
            amt = float(str(d.get("LineTotal") or 0) or 0)
        except Exception:
            amt = 0.0
        em = str(d.get("SubmittedBy") or "").strip().lower()
        out[em] = out.get(em, 0.0) + amt
    return out


def _budget_check(eng, cust: str, p, content: dict) -> list:
    """Sentences describing every budget this order pushes past, or []."""
    order_no = str(content.get("OrderNumber") or "")
    try:
        total = float(str(content.get("TotalAmount") or content.get("LineTotal") or 0) or 0)
    except Exception:
        total = 0.0
    spend = _month_spend(eng, cust, exclude_order=order_no)
    notes = []
    pb = _money(p["budget"])
    mine = spend.get(str(p["email"]).lower(), 0.0)
    if pb is not None and mine + total > pb:
        notes.append(f"{p['user_label'] or p['email']} is over its ${pb:,.0f} monthly budget "
                     f"(${mine + total:,.0f} with this order)")
    my_groups = _person_group_names(cust, p["group2"], p["group1"])
    if my_groups:
        from sqlalchemy import text
        with eng.connect() as c:
            allp = c.execute(text("select email, group1, group2 from cat_people")).all()
        chains = {str(e).lower(): _person_group_names(cust, g2, g1) for e, g1, g2 in allp}
        for gname in sorted(my_groups):
            g = _group_row(cust, gname)
            gb = _money(g["budget"]) if g is not None else None
            if gb is None:
                continue
            gspend = sum(v for em, v in spend.items() if gname in chains.get(em, set()))
            if gspend + total > gb:
                notes.append(f"group {gname} is over its ${gb:,.0f} monthly budget "
                             f"(${gspend + total:,.0f} with this order)")
    return notes


def _group_row(cust: str, name: str):
    if not name:
        return None
    from sqlalchemy import text
    try:
        with _builder_engine().connect() as c:
            return c.execute(text("select * from cat_groups where customer=:c and name=:n"),
                             {"c": cust, "n": name}).mappings().first()
    except Exception:
        return None


def _effective_access(p, cust: str):
    """(mode, vendors) for a person. Their own only/except setting wins;
    otherwise their groups answer — Group 2 first (the more specific), then
    Group 1, each walking up parents so a grant to a parent group cascades
    down to every group within it. Nothing set anywhere means all vendors."""
    mode = str(p["vendors_mode"] or "all")
    if mode in ("only", "except"):
        try:
            return mode, json.loads(p["vendors"] or "[]")
        except Exception:
            return mode, []
    for gname in (str(p["group2"] or "").strip(), str(p["group1"] or "").strip()):
        seen = set()
        g = _group_row(cust, gname)
        while g is not None and g["name"] not in seen and len(seen) < 12:
            seen.add(g["name"])
            gmode = str(g["vendors_mode"] or "all")
            if gmode in ("only", "except"):
                try:
                    return gmode, json.loads(g["vendors"] or "[]")
                except Exception:
                    return gmode, []
            g = _group_row(cust, str(g["parent"] or "").strip())
    return "all", []


def _effective_perms(p, cust: str) -> dict:
    """Tab reach, resolved the same way as vendor access: the person's own
    explicit settings win key by key, then Group 2's chain, then Group 1's,
    and anything still unset falls to wide open."""
    chain = []
    try:
        chain.append(_clean_perms(json.loads(p["perms"] or "{}")))
    except Exception:
        chain.append({})
    for gname in (str(p["group2"] or "").strip(), str(p["group1"] or "").strip()):
        seen = set()
        g = _group_row(cust, gname)
        while g is not None and g["name"] not in seen and len(seen) < 12:
            seen.add(g["name"])
            try:
                chain.append(_clean_perms(json.loads(g["perms"] or "{}")))
            except Exception:
                pass
            g = _group_row(cust, str(g["parent"] or "").strip())
    out = dict(_PERM_DEFAULT)
    for k in ("catalog", "order", "pending"):
        for d in chain:
            if k in d:
                out[k] = d[k]
                break
    return out


def _person_scope(p) -> dict:
    cust = str(p["customer"] or "").strip() or _builder_only_customer()
    if p["admin"]:
        return {"all": True, "customer": cust, "vendors_all": True, "vendors": [],
                "perms": dict(_PERM_DEFAULT)}
    mode, vens = _effective_access(p, cust)
    return {"all": False, "customer": cust, "vendors_all": mode == "all",
            "vendors": vens, "vendors_mode": mode, "perms": _effective_perms(p, cust),
            "user": p["user_label"], "group_1": p["group1"], "group_2": p["group2"]}


async def _whoami(request: Request):
    """One answer to 'who is asking' — this app's own people first, the ETL
    session as the fallback while the move is still in progress."""
    tok = request.cookies.get(SESSION_COOKIE, "").strip('"')
    if not tok:
        return None
    if tok.startswith("v1."):
        email = _local_token_email(tok)
        p = _person(email) if email else None
        if p is None:
            return None
        return {"email": email, "admin": bool(p["admin"]), "local": True,
                "must_change": bool(p["must_change"]), "scope": _person_scope(p)}
    if ETL_BASE:
        try:
            me = await etl_get("/api/access/me", request=request)
            sc = (me or {}).get("scope") or {}
            return {"email": str((me or {}).get("email") or ""), "local": False,
                    "admin": _scope_administers(sc), "must_change": False, "scope": sc}
        except HTTPException:
            return None
    return None


async def _people_gate(request: Request):
    who = await _whoami(request)
    if who is None:
        raise HTTPException(401, "Not signed in.")
    if not who["admin"]:
        raise HTTPException(403, "Only an administrator can manage people.")
    return who


@app.get("/api/admin/people")
async def people_list(request: Request):
    await _people_gate(request)
    if not _people_on():
        raise HTTPException(400, "The catalog's own database is not connected yet.")
    from sqlalchemy import text
    eng = _builder_engine()
    with eng.connect() as c:
        rows = c.execute(text("select * from cat_people order by group1, user_label, email"))\
                .mappings().all()
    spend = _month_spend(eng, _builder_only_customer() or "main")
    out = []
    for p in rows:
        try:
            vens = json.loads(p["vendors"] or "[]")
        except Exception:
            vens = []
        try:
            prm = _clean_perms(json.loads(p["perms"] or "{}"))
        except Exception:
            prm = {}
        out.append({"email": p["email"], "user": p["user_label"],
                    "group1": p["group1"], "group2": p["group2"],
                    "admin": bool(p["admin"]), "perms": prm,
                    "budget": p["budget"] or "",
                    "spent": round(spend.get(str(p["email"]).lower(), 0.0), 2),
                    "vendors_mode": str(p["vendors_mode"] or "all"), "vendors": vens,
                    "pw": ("must_change" if p["must_change"] else "set") if p["pw_hash"]
                          else "never",
                    "last_signin": p["last_signin"] or ""})
    return {"ok": True, "people": out}


@app.post("/api/admin/people")
async def people_save(request: Request):
    who = await _people_gate(request)
    body = await request.json() or {}
    email = str(body.get("email") or "").strip().lower()
    if "@" not in email or "." not in email or len(email) > 200:
        raise HTTPException(400, "That does not look like an email address.")
    admin = bool(body.get("admin"))
    if email == who["email"] and who.get("local") and not admin:
        raise HTTPException(400, "You cannot take away your own administrator access.")
    mode = str(body.get("vendors_mode") or "all").lower()
    if mode not in ("all", "only", "except"):
        raise HTTPException(400, "Vendor access must be all, only, or except.")
    vens = [str(v)[:120] for v in (body.get("vendors") or []) if str(v).strip()][:500]
    vals = {"e": email, "u": str(body.get("user") or "").strip()[:120],
            "g1": str(body.get("group1") or "").strip()[:120],
            "g2": str(body.get("group2") or "").strip()[:120],
            "a": admin, "vm": mode, "vs": json.dumps(vens),
            "pm": json.dumps(_clean_perms(body.get("perms"))),
            "b": str(body.get("budget") or "").strip()[:40],
            "c": _builder_only_customer()}
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        row = c.execute(text("select email from cat_people where email=:e"),
                        {"e": email}).first()
        if row:
            c.execute(text("update cat_people set user_label=:u, group1=:g1, group2=:g2, "
                           "admin=:a, vendors_mode=:vm, vendors=:vs, perms=:pm, budget=:b "
                           "where email=:e"), vals)
        else:
            c.execute(text("insert into cat_people(email,customer,user_label,group1,group2,"
                           "admin,vendors_mode,vendors,perms,budget) "
                           "values(:e,:c,:u,:g1,:g2,:a,:vm,:vs,:pm,:b)"), vals)
    return {"ok": True, "added": not bool(row),
            "message": ("Added " if not row else "Updated ") + email +
                       (". Set their password on the Passwords tab before they can sign in."
                        if not row else ".")}


@app.post("/api/admin/people/delete")
async def people_delete(request: Request):
    who = await _people_gate(request)
    body = await request.json() or {}
    email = str(body.get("email") or "").strip().lower()
    if email == who["email"]:
        raise HTTPException(400, "You cannot delete yourself.")
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        c.execute(text("delete from cat_people where email=:e"), {"e": email})
    return {"ok": True, "message": f"Removed {email}. They can no longer sign in."}


@app.post("/api/admin/people/password")
async def people_password(request: Request):
    await _people_gate(request)
    body = await request.json() or {}
    email = str(body.get("email") or "").strip().lower()
    pw = str(body.get("password") or "")
    if len(pw) < 8:
        raise HTTPException(400, "Passwords need at least 8 characters.")
    if _person(email) is None:
        raise HTTPException(404, "No such person — add them on the Users tab first.")
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        c.execute(text("update cat_people set pw_hash=:h, must_change=:m where email=:e"),
                  {"h": _pw_make(pw), "m": bool(body.get("must_change", True)), "e": email})
    return {"ok": True, "message": f"Password set for {email}."}


@app.post("/api/admin/people/force-reset")
async def people_force_reset(request: Request):
    await _people_gate(request)
    body = await request.json() or {}
    email = str(body.get("email") or "").strip().lower()
    if _person(email) is None:
        raise HTTPException(404, "No such person.")
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        c.execute(text("update cat_people set pw_hash='', must_change=false where email=:e"),
                  {"e": email})
    return {"ok": True, "message": f"{email} can no longer sign in until a new password is set."}


def _built_vendors(eng, cust: str) -> list:
    from sqlalchemy import text
    try:
        with eng.connect() as c:
            b = c.execute(text("select table_name from cat_built where customer=:c"),
                          {"c": cust}).first()
            if not b:
                b = c.execute(text("select table_name from cat_built limit 1")).first()
            if not b:
                return []
            return sorted({str(r[0]).strip() for r in c.execute(text(
                f'select distinct "Vendor" from "{b[0]}"')) if str(r[0]).strip()})
    except Exception:
        return []


async def _aux_rows_local(ident: str, request: Request):
    """Store/district and vendor-ordering rows, answered from this app's own
    store. The order form reads these; they used to be ETL datasets. Stores
    and districts come straight from the people rows: the user label is the
    store ("104 - MCALLEN"), Group 2 is the district where one exists, and a
    person whose Group 1 says district or region is that district's manager.
    A catalog with no districts simply leaves Group 2 blank — nothing else
    to set up."""
    try:
        if not os.environ.get("CATALOG_DATABASE_URL", "").strip():
            return None
        key = _bnorm(ident)
        if key not in ("storemapping", "vendorinfolist", "vendorinfo"):
            return None
        who = await _whoami(request)
        if who is None:
            return None
        sc = who.get("scope") or {}
        cust = _bslug(str(sc.get("customer") or "")) if str(sc.get("customer") or "").strip() else ""
        if not cust or cust == "x":
            cust = _builder_only_customer() or "main"
        import pandas as pd
        from sqlalchemy import text
        eng = _builder_engine()
        if key in ("vendorinfolist", "vendorinfo"):
            with eng.connect() as c:
                rows = c.execute(text("select * from cat_vendorinfo where customer=:c "
                                      "order by vendor"), {"c": cust}).mappings().all()
            by_v = {r["vendor"]: r for r in rows}
            recs = []
            for v in (_built_vendors(eng, cust) or list(by_v.keys())):
                r = by_v.get(v)
                recs.append({"Vendor": v,
                             "OrderEmail": r["order_email"] if r else "",
                             "FreightMin": r["freight_min"] if r else "",
                             "FreightMinbyCat": r["freight_min_by_cat"] if r else "",
                             "FreightMinbyBrand": r["freight_min_by_brand"] if r else "",
                             "FreightMinQtyorTotalCost": r["freight_qty_or_cost"] if r else ""})
            df = pd.DataFrame(recs)
        else:
            with eng.connect() as c:
                ppl = c.execute(text("select * from cat_people order by group2, user_label"))\
                        .mappings().all()
            recs = []
            for p in ppl:
                label = str(p["user_label"] or "").strip()
                if not label:
                    continue
                num, name = label, label
                for sep in (" - ", " – ", "-"):
                    if sep in label:
                        num, name = label.split(sep, 1)[0].strip(), label.split(sep, 1)[1].strip()
                        break
                g1 = str(p["group1"] or "").lower()
                isd = ("district" in g1) or ("region" in g1)
                recs.append({"DistrictID": str(p["group2"] or "").strip(),
                             "StoreNum": "" if isd else num,
                             "StoreName": "" if isd else name,
                             "GeneralManagersName": name,
                             "StoreEmail": "" if isd else p["email"],
                             "ManagerEmail": "" if isd else p["email"],
                             "DistrictManager": name if isd else "",
                             "DistrictManagerEmail": p["email"] if isd else "",
                             "PurchasingDirector": "", "RegionID": ""})
            df = pd.DataFrame(recs)
        if df.empty:
            return JSONResponse([])
        params = dict(request.query_params)
        want = [c.strip() for c in (params.get("groupby") or params.get("fields") or "")
                .split(",") if c.strip()]
        if want:
            by_norm = {}
            for c in df.columns:
                by_norm.setdefault(_bnorm(c), c)
            have = list(dict.fromkeys(by_norm[_bnorm(w)] for w in want if _bnorm(w) in by_norm))
            if have:
                df = df[have]
                if params.get("groupby"):
                    df = df.drop_duplicates()
        return JSONResponse(json.loads(df.to_json(orient="records")))
    except Exception:
        return None


@app.get("/api/app/my-budget")
async def my_budget(request: Request):
    """Where the signed-in person stands against their budgets this month —
    the order form shows it next to the cart total."""
    who = await _whoami(request)
    if who is None:
        raise HTTPException(401, "Not signed in.")
    if not who.get("local") or who.get("admin") or not _people_on():
        return {"budgets": []}
    p = _person(str(who.get("email") or ""))
    if p is None:
        return {"budgets": []}
    cust = str(p["customer"] or "").strip() or _builder_only_customer() or "main"
    eng = _builder_engine()
    spend = _month_spend(eng, cust)
    out = []
    pb = _money(p["budget"])
    if pb is not None:
        out.append({"name": p["user_label"] or "this location", "budget": pb,
                    "spent": round(spend.get(str(p["email"]).lower(), 0.0), 2)})
    my_groups = _person_group_names(cust, p["group2"], p["group1"])
    if my_groups:
        from sqlalchemy import text
        with eng.connect() as c:
            allp = c.execute(text("select email, group1, group2 from cat_people")).all()
        chains = {str(e).lower(): _person_group_names(cust, g2, g1) for e, g1, g2 in allp}
        for gname in sorted(my_groups):
            g = _group_row(cust, gname)
            gb = _money(g["budget"]) if g is not None else None
            if gb is None:
                continue
            gspent = sum(v for em, v in spend.items() if gname in chains.get(em, set()))
            out.append({"name": "group " + gname, "budget": gb, "spent": round(gspent, 2)})
    return {"budgets": out}


@app.get("/api/admin/groups")
async def groups_list(request: Request):
    await _people_gate(request)
    cust = _builder_only_customer() or "main"
    from sqlalchemy import text
    with _builder_engine().connect() as c:
        rows = c.execute(text("select * from cat_groups where customer=:c order by name"),
                         {"c": cust}).mappings().all()
        counts = {}
        for g1, g2 in c.execute(text("select group1, group2 from cat_people")):
            for n in (str(g1 or "").strip(), str(g2 or "").strip()):
                if n:
                    counts[n] = counts.get(n, 0) + 1
    out = []
    for g in rows:
        try:
            vens = json.loads(g["vendors"] or "[]")
        except Exception:
            vens = []
        try:
            prm = _clean_perms(json.loads(g["perms"] or "{}"))
        except Exception:
            prm = {}
        out.append({"name": g["name"], "parent": g["parent"] or "",
                    "vendors_mode": str(g["vendors_mode"] or "all"), "vendors": vens,
                    "perms": prm, "budget": g["budget"] or "",
                    "members": counts.get(g["name"], 0)})
    return {"ok": True, "groups": out}


@app.post("/api/admin/groups")
async def groups_save(request: Request):
    await _people_gate(request)
    body = await request.json() or {}
    name = str(body.get("name") or "").strip()[:120]
    if not name:
        raise HTTPException(400, "A group needs a name.")
    parent = str(body.get("parent") or "").strip()[:120]
    if parent == name:
        raise HTTPException(400, "A group cannot be inside itself.")
    mode = str(body.get("vendors_mode") or "all").lower()
    if mode not in ("all", "only", "except"):
        raise HTTPException(400, "Vendor access must be all, only, or except.")
    vens = [str(v)[:120] for v in (body.get("vendors") or []) if str(v).strip()][:500]
    cust = _builder_only_customer() or "main"
    pm = json.dumps(_clean_perms(body.get("perms")))
    bud = str(body.get("budget") or "").strip()[:40]
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        n = c.execute(text("update cat_groups set parent=:p, vendors_mode=:m, vendors=:v, "
                           "perms=:pm, budget=:b where customer=:c and name=:n"),
                      {"p": parent, "m": mode, "v": json.dumps(vens), "pm": pm, "b": bud,
                       "c": cust, "n": name}).rowcount
        if not n:
            c.execute(text("insert into cat_groups(customer,name,parent,vendors_mode,vendors,"
                           "perms,budget) values(:c,:n,:p,:m,:v,:pm,:b)"),
                      {"c": cust, "n": name, "p": parent, "m": mode,
                       "v": json.dumps(vens), "pm": pm, "b": bud})
    return {"ok": True, "message": f"Saved group {name}."}


@app.post("/api/admin/groups/members")
async def groups_members(request: Request):
    """Put people into a group, or take them out, from the group's side.
    A person has two group slots — joining fills the first empty one, and
    leaving clears whichever slot named this group."""
    await _people_gate(request)
    body = await request.json() or {}
    name = str(body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "Which group?")
    add = [str(e).strip().lower() for e in (body.get("add") or []) if str(e).strip()]
    remove = [str(e).strip().lower() for e in (body.get("remove") or []) if str(e).strip()]
    from sqlalchemy import text
    full, moved = [], 0
    with _builder_engine().begin() as c:
        for email in add:
            row = c.execute(text("select group1, group2 from cat_people where email=:e"),
                            {"e": email}).first()
            if row is None:
                continue
            g1, g2 = str(row[0] or "").strip(), str(row[1] or "").strip()
            if name in (g1, g2):
                continue
            if not g1:
                c.execute(text("update cat_people set group1=:n where email=:e"),
                          {"n": name, "e": email})
            elif not g2:
                c.execute(text("update cat_people set group2=:n where email=:e"),
                          {"n": name, "e": email})
            else:
                full.append(email)
                continue
            moved += 1
        for email in remove:
            row = c.execute(text("select group1, group2 from cat_people where email=:e"),
                            {"e": email}).first()
            if row is None:
                continue
            if str(row[0] or "").strip() == name:
                c.execute(text("update cat_people set group1='' where email=:e"), {"e": email})
                moved += 1
            elif str(row[1] or "").strip() == name:
                c.execute(text("update cat_people set group2='' where email=:e"), {"e": email})
                moved += 1
    msg = f"{moved} change{'' if moved == 1 else 's'} to {name}."
    if full:
        msg += (" Not added (both group slots already used): " + ", ".join(full[:5]) +
                " \u2014 clear one of their groups on their row first.")
    return {"ok": True, "message": msg, "refused": full}


@app.post("/api/admin/groups/delete")
async def groups_delete(request: Request):
    await _people_gate(request)
    body = await request.json() or {}
    name = str(body.get("name") or "").strip()
    cust = _builder_only_customer() or "main"
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        c.execute(text("delete from cat_groups where customer=:c and name=:n"),
                  {"c": cust, "n": name})
        c.execute(text("update cat_groups set parent='' where customer=:c and parent=:n"),
                  {"c": cust, "n": name})
    return {"ok": True, "message": f"Removed group {name}. People keep the label; it just "
                                   f"no longer carries access."}


@app.get("/api/admin/vendorinfo")
async def vendorinfo_list(request: Request):
    """Every vendor of the built catalog, with where their orders go."""
    await _people_gate(request)
    from sqlalchemy import text
    eng = _builder_engine()
    cust = _builder_only_customer() or "main"
    with eng.connect() as c:
        rows = c.execute(text("select * from cat_vendorinfo where customer=:c"),
                         {"c": cust}).mappings().all()
    by_v = {r["vendor"]: r for r in rows}
    out = []
    for v in sorted(set(_built_vendors(eng, cust)) | set(by_v.keys())):
        r = by_v.get(v)
        out.append({"vendor": v,
                    "order_email": r["order_email"] if r else "",
                    "freight_min": r["freight_min"] if r else "",
                    "freight_min_by_cat": r["freight_min_by_cat"] if r else "",
                    "freight_min_by_brand": r["freight_min_by_brand"] if r else "",
                    "freight_qty_or_cost": r["freight_qty_or_cost"] if r else ""})
    return {"ok": True, "vendors": out}


@app.post("/api/admin/vendorinfo")
async def vendorinfo_save(request: Request):
    await _people_gate(request)
    body = await request.json() or {}
    vendor = str(body.get("vendor") or "").strip()
    if not vendor:
        raise HTTPException(400, "Which vendor?")
    vals = {"c": _builder_only_customer() or "main", "v": vendor[:120],
            "e": str(body.get("order_email") or "").strip()[:200],
            "f1": str(body.get("freight_min") or "").strip()[:80],
            "f2": str(body.get("freight_min_by_cat") or "").strip()[:80],
            "f3": str(body.get("freight_min_by_brand") or "").strip()[:80],
            "f4": str(body.get("freight_qty_or_cost") or "").strip()[:80]}
    from sqlalchemy import text
    with _builder_engine().begin() as c:
        n = c.execute(text("update cat_vendorinfo set order_email=:e, freight_min=:f1, "
                           "freight_min_by_cat=:f2, freight_min_by_brand=:f3, "
                           "freight_qty_or_cost=:f4 where customer=:c and vendor=:v"),
                      vals).rowcount
        if not n:
            c.execute(text("insert into cat_vendorinfo(customer,vendor,order_email,freight_min,"
                           "freight_min_by_cat,freight_min_by_brand,freight_qty_or_cost) "
                           "values(:c,:v,:e,:f1,:f2,:f3,:f4)"), vals)
    return {"ok": True, "message": f"Saved {vendor}."}


@app.get("/api/admin/people/vendors")
async def people_vendors(request: Request):
    """Every vendor in the built catalog — the tick list for vendor access."""
    await _people_gate(request)
    from sqlalchemy import text
    vals = []
    try:
        eng = _builder_engine()
        with eng.connect() as c:
            built = c.execute(text("select table_name from cat_built limit 1")).first()
            if built:
                vals = sorted({str(r[0]).strip() for r in c.execute(text(
                    f'select distinct "Vendor" from "{built[0]}"')) if str(r[0]).strip()})
    except Exception:
        vals = []
    return {"ok": True, "vendors": vals[:2000]}


# ════════════════════════════════════════════════════════════════════════════
# FEEDS — the connectors. How a source refreshes itself without a hand upload.
#
# Each source card can carry a feed: API (this app pulls a URL), SFTP (this app
# signs into the vendor's server and takes the newest matching file), or EMAIL
# (vendors mail the file to a mailbox this app checks; matched by sender).
# A timer runs the due feeds; when a pull brings a genuinely new file, the
# source's table is replaced, the mapping is re-checked, and the catalog is
# rebuilt on the spot — the storefront updates with nobody touching anything.
# ════════════════════════════════════════════════════════════════════════════

_FEED_TYPES = ("manual", "api", "sftp", "email")
_PW_KEPT = "•kept•"          # what a stored password looks like on the way OUT


def _feed_of(row) -> dict:
    try:
        f = json.loads(row["feed"] or "{}")
    except Exception:
        f = {}
    return f if isinstance(f, dict) else {}


def _feed_status_of(row) -> dict:
    try:
        s = json.loads(row["feed_status"] or "{}")
    except Exception:
        s = {}
    return s if isinstance(s, dict) else {}


def _email_env():
    return (os.environ.get("EMAIL_IMAP_HOST", "").strip(),
            int(os.environ.get("EMAIL_IMAP_PORT", "993") or 993),
            os.environ.get("EMAIL_IMAP_USER", "").strip(),
            os.environ.get("EMAIL_IMAP_PASS", "").strip())


def _builder_read_frame(filename: str, raw: bytes):
    """Bytes → dataframe, the one way every connector and the upload box share."""
    import io
    import pandas as pd
    if not raw:
        raise ValueError("The file arrived empty.")
    if len(raw) > 80 * 1024 * 1024:
        raise ValueError("That file is over 80 MB — trim it or split it first.")
    try:
        if str(filename).lower().endswith((".xlsx", ".xlsm", ".xls")):
            df = pd.read_excel(io.BytesIO(raw))
        else:
            df = pd.read_csv(io.BytesIO(raw), dtype=str, keep_default_na=False,
                             encoding_errors="replace")
    except Exception as e:
        raise ValueError(f"Could not read that file: {e}")
    if df.empty or not len(df.columns):
        raise ValueError("The file has no rows.")
    df.columns = [str(c).strip() for c in df.columns]
    return df


def _feed_fetch_api(cfg: dict, progress=None):
    url = str(cfg.get("url") or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("The URL must start with http:// or https://")
    headers = {}
    for part in [p for p in
                 str(cfg.get("header") or "").replace("\n", ";").split(";") if p.strip()]:
        if ":" in part:
            k, v = part.split(":", 1)
            headers[k.strip()] = v.strip()
    auth = None
    if str(cfg.get("auth_user") or "").strip():
        auth = (str(cfg.get("auth_user")).strip(), str(cfg.get("auth_pass") or ""))
    # OAuth client-credentials: trade the client id + secret for a short-lived
    # token first, then call the API with it. Tried both common styles.
    tok_url = str(cfg.get("token_url") or "").strip()
    cid = str(cfg.get("client_id") or "").strip()
    if tok_url and cid:
        csec = str(cfg.get("client_secret") or "")
        with httpx.Client(timeout=60, follow_redirects=True) as tc:
            tr = tc.post(tok_url, data={"grant_type": "client_credentials",
                                        "client_id": cid, "client_secret": csec})
            if tr.status_code >= 400:
                tr = tc.post(tok_url, data={"grant_type": "client_credentials"},
                             auth=(cid, csec))
        if tr.status_code >= 400:
            raise ValueError(f"The token service answered {tr.status_code} — check the "
                             f"token URL, client ID and client secret.")
        try:
            tok = str(tr.json().get("access_token") or "")
        except Exception:
            tok = ""
        if not tok:
            raise ValueError("The token service answered, but returned no access_token.")
        headers.setdefault("Authorization", "Bearer " + tok)
    qparams = [(str(k), str(v)) for k, v in (cfg.get("qparams") or [])
               if str(k).strip()]
    def _unwrap(payload):
        """Find the list of records wherever the API nested it: known wrapper
        keys first, then a recursive hunt for the largest list of objects."""
        def hunt(node, depth=0):
            if isinstance(node, list):
                if node and all(isinstance(x, dict) for x in node[:20]):
                    return node
                return None
            if isinstance(node, dict) and depth < 5:
                best = None
                for v in node.values():
                    got = hunt(v, depth + 1)
                    if got is not None and (best is None or len(got) > len(best)):
                        best = got
                return best
            return None
        if isinstance(payload, dict):
            for key in ("data", "items", "rows", "results", "products"):
                if isinstance(payload.get(key), list) and payload[key] \
                        and all(isinstance(x, dict) for x in payload[key][:20]):
                    return payload[key]
            found = hunt(payload)
            if found is not None:
                return found
        return payload

    with httpx.Client(timeout=120, follow_redirects=True, auth=auth) as cl:
        r = cl.get(url, headers=headers, params=qparams or None)
        if r.status_code != 200:
            raise ValueError(f"The API answered {r.status_code}.")
        data = r.content
        ctype = r.headers.get("content-type", "")
        base = url.rsplit("/", 1)[-1].split("?")[0] or "feed"
        is_file = base.lower().endswith((".csv", ".xlsx", ".xls", ".xlsm"))
        name = base if "." in base else base + (".xlsx" if "sheet" in ctype else ".csv")
        if "json" in ctype and not is_file:
            # A JSON API — a list of records becomes the table. When a limit
            # parameter is set and a page comes back full, keep turning pages
            # (Ashley-style pagination) until a short page says done.
            import io
            import pandas as pd

            def _flat(rec):
                """One record -> one flat row, without letting nested lists
                explode into hundreds of columns (that is what crashes a small
                instance). Scalars kept; one level of dict unpacked; anything
                deeper becomes a compact JSON string."""
                out = {}

                def put_dict(prefix, d):
                    for k2, v2 in d.items():
                        if isinstance(v2, (str, int, float, bool)) or v2 is None:
                            out[f"{prefix}.{k2}"] = v2
                        elif isinstance(v2, dict):
                            for k3, v3 in v2.items():
                                if isinstance(v3, (str, int, float, bool)) or v3 is None:
                                    out[f"{prefix}.{k2}.{k3}"] = v3
                                else:
                                    out[f"{prefix}.{k2}.{k3}"] = json.dumps(v3)[:300]
                        else:
                            out[f"{prefix}.{k2}"] = json.dumps(v2)[:300]

                for k, v in rec.items():
                    k = str(k)
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        out[k] = v
                    elif isinstance(v, dict):
                        put_dict(k, v)
                    elif isinstance(v, list) and v and isinstance(v[0], dict):
                        # a list of objects: unpack the first one into columns
                        # (price lists, image lists) and keep the rest compact
                        put_dict(k, v[0])
                        if len(v) > 1:
                            out[k] = json.dumps(v)[:300]
                    else:
                        out[k] = json.dumps(v)[:300]
                return out

            raw_json = json.loads(data.decode("utf-8", "replace"))
            parsed = _unwrap(raw_json)
            if not isinstance(parsed, list) or not parsed:
                shape = (", ".join(list(raw_json.keys())[:8])
                         if isinstance(raw_json, dict) else type(raw_json).__name__)
                raise ValueError("The API returned JSON, but no list of records was found "
                                 f"inside it (top-level keys: {shape}).")
            records = [_flat(r) for r in parsed if isinstance(r, dict)]
            first_page_n = len(parsed)
            raw_json = parsed = None      # free the parsed page before the next
            import gc
            gc.collect()
            if progress:
                progress(1, len(records))
            qd = {str(k).lower(): str(v) for k, v in qparams}
            try:
                limit_val = int(qd.get("limit") or 0)
            except Exception:
                limit_val = 0
            if limit_val > 0 and first_page_n >= limit_val and "page" not in qd:
                page = 2
                while page <= 200:
                    r2 = cl.get(url, headers=headers,
                                params=qparams + [("page", str(page))])
                    if r2.status_code != 200:
                        break
                    try:
                        more = _unwrap(json.loads(r2.content.decode("utf-8", "replace")))
                    except Exception:
                        break
                    if not isinstance(more, list) or not more:
                        break
                    records.extend(_flat(x) for x in more if isinstance(x, dict))
                    short = len(more) < limit_val
                    more = None
                    gc.collect()
                    if progress:
                        progress(page, len(records))
                    if short or len(records) >= 150000:
                        break
                    page += 1
            df = pd.DataFrame(records)
            buf = io.BytesIO()
            df.to_csv(buf, index=False)
            data, name = buf.getvalue(), "feed.csv"
    return name, data


def _feed_fetch_sftp(cfg: dict):
    import fnmatch
    import io
    import stat as statmod
    try:
        import paramiko
    except ImportError:
        raise ValueError("SFTP support is not installed on this service yet "
                         "(requirements.txt needs paramiko).")
    host = str(cfg.get("host") or "").strip()
    if not host:
        raise ValueError("SFTP needs a host.")
    port = int(cfg.get("port") or 22)
    user = str(cfg.get("user") or "").strip()
    pw = str(cfg.get("password") or "")
    path = str(cfg.get("path") or "/").strip() or "/"
    pattern = str(cfg.get("pattern") or "*").strip() or "*"
    t = paramiko.Transport((host, port))
    try:
        t.connect(username=user, password=pw)
        sftp = paramiko.SFTPClient.from_transport(t)
        try:
            st = sftp.stat(path)
            isdir = statmod.S_ISDIR(st.st_mode)
        except IOError:
            raise ValueError(f"No such path on the server: {path}")
        if isdir:
            best = None
            for e in sftp.listdir_attr(path):
                if statmod.S_ISDIR(e.st_mode):
                    continue
                if not fnmatch.fnmatch(e.filename, pattern):
                    continue
                if best is None or (e.st_mtime or 0) > (best.st_mtime or 0):
                    best = e
            if best is None:
                raise ValueError(f"Nothing matching {pattern} in {path}.")
            fname = best.filename
            full = path.rstrip("/") + "/" + fname
        else:
            fname, full = path.rsplit("/", 1)[-1], path
        buf = io.BytesIO()
        sftp.getfo(full, buf)
        return fname, buf.getvalue()
    finally:
        try:
            t.close()
        except Exception:
            pass


def _feed_address(sid: str) -> str:
    """This source's own inbound address — plus-addressing on the connected
    mailbox, so vendors@anywhere can send straight to one source."""
    user = os.environ.get("EMAIL_IMAP_USER", "").strip()
    if not user or "@" not in user or not sid:
        return ""
    local, dom = user.split("@", 1)
    return f"{local}+cat{sid}@{dom}"


def _feed_fetch_email(cfg: dict, sid: str = ""):
    host, port, user, pw = _email_env()
    if not (host and user and pw):
        raise ValueError("Connect a mailbox first: on this service's Environment page in Render, "
                         "set EMAIL_IMAP_HOST, EMAIL_IMAP_USER and EMAIL_IMAP_PASS "
                         "(and EMAIL_IMAP_PORT if it is not 993).")
    frm = str(cfg.get("from_contains") or "").strip()
    subj = str(cfg.get("subject_contains") or "").strip()
    addr = _feed_address(sid)
    if frm:
        crit = f'FROM "{frm}"' + (f' SUBJECT "{subj}"' if subj else "")
    elif addr:
        crit = f'TO "{addr}"' + (f' SUBJECT "{subj}"' if subj else "")
    else:
        raise ValueError("Say what the sender's address contains, so the right mail is picked.")
    import email as email_mod
    import imaplib
    M = imaplib.IMAP4_SSL(host, port)
    try:
        M.login(user, pw)
        M.select("INBOX", readonly=True)
        typ, data = M.search(None, f'({crit})')
        ids = (data[0] or b"").split()
        if not ids:
            raise ValueError(("No mail from that sender yet." if frm else
                              f"Nothing sent to {addr} yet."))
        for mid in reversed(ids[-20:]):          # newest first, recent 20 only
            typ, msgd = M.fetch(mid, "(RFC822)")
            if typ != "OK" or not msgd or not msgd[0]:
                continue
            msg = email_mod.message_from_bytes(msgd[0][1])
            for part in msg.walk():
                fn = str(part.get_filename() or "")
                if fn.lower().endswith((".csv", ".xlsx", ".xlsm", ".xls")):
                    payload = part.get_payload(decode=True)
                    if payload:
                        return fn, payload
        raise ValueError("Mail found, but no spreadsheet attachment on the recent ones.")
    finally:
        try:
            M.logout()
        except Exception:
            pass


def _feed_alert(subject: str, body: str) -> bool:
    """Mail the person who runs this catalog when a feed needs a human.
    Uses SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/SMTP_FROM and ALERT_EMAIL from
    the Environment page. Quietly does nothing until those are set."""
    host = os.environ.get("SMTP_HOST", "").strip()
    to = os.environ.get("ALERT_EMAIL", "").strip()
    if not host or not to:
        return False
    try:
        import smtplib
        from email.message import EmailMessage
        port = int(os.environ.get("SMTP_PORT", "587") or 587)
        user = os.environ.get("SMTP_USER", "").strip()
        pw = os.environ.get("SMTP_PASS", "")
        frm = os.environ.get("SMTP_FROM", "").strip() or user or to
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"], msg["To"] = frm, to
        msg.set_content(body)
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=20) as s:
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.starttls()
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        return True
    except Exception:
        return False


def _feed_run_source(eng, row) -> dict:
    """Fetch one source's feed and refresh its table. Always records a status,
    and raises an alert when a file fails or stops matching the schema."""
    from sqlalchemy import text
    cfg = _feed_of(row)
    kind = str(cfg.get("type") or "manual")
    prev = _feed_status_of(row)
    out = {"last_run": time.strftime("%Y-%m-%d %H:%M"), "last_ts": time.time(),
           "ok": False, "changed": False, "note": ""}
    def _progress(page, count):
        try:
            from sqlalchemy import text as _t
            note = f"Downloading — page {page}, {count:,} records so far…"
            with eng.begin() as c:
                c.execute(_t("update cat_sources set feed_status=:s where id=:i"),
                          {"s": json.dumps({"running": True, "note": note,
                                            "last_run": out["last_run"],
                                            "last_ts": out["last_ts"],
                                            "sha": prev.get("sha", "")}),
                           "i": row["id"]})
        except Exception:
            pass

    try:
        if kind == "api":
            fname, raw = _feed_fetch_api(cfg, progress=_progress)
        elif kind == "sftp":
            fname, raw = _feed_fetch_sftp(cfg)
        elif kind == "email":
            fname, raw = _feed_fetch_email(cfg, str(row["id"]))
        else:
            raise ValueError("This source has no feed.")
        sha = hashlib.sha256(raw).hexdigest()
        if prev.get("sha") == sha:
            out.update(ok=True, sha=sha, note="Checked — same file as last time.")
        else:
            df = _builder_read_frame(fname, raw)
            df.astype(str).to_sql(row["table_name"], eng, if_exists="replace",
                                  index=False, chunksize=2000)
            try:
                m = json.loads(row["mapping"] or "{}")
            except Exception:
                m = {}
            cols = {str(c) for c in df.columns}
            m = {k: v for k, v in m.items() if v in cols}     # drop vanished columns
            for k, v in _builder_automap(df.columns).items():  # recognise new ones
                m.setdefault(k, v)
            with eng.begin() as c:
                c.execute(text("update cat_sources set filename=:f, row_count=:r, mapping=:m, "
                               "updated_at=current_timestamp where id=:i"),
                          {"f": str(fname)[:120], "r": int(len(df)),
                           "m": json.dumps(m), "i": row["id"]})
            miss = _builder_missing(m, row["vendor_label"])
            if miss:
                out.update(ok=False, changed=True, sha=sha, rows=int(len(df)), schema=True,
                           note=f"Pulled {fname} ({len(df)} rows) but its columns no longer "
                                f"cover: {', '.join(miss)}. Open the card and pick them.")
                _feed_alert(f"Catalog feed needs attention: {row['name']}",
                            f"The feed for \"{row['name']}\" pulled {fname} ({len(df)} rows), "
                            f"but these required fields have no matching column any more: "
                            f"{', '.join(miss)}.\n\nThe catalog was NOT rebuilt from it. "
                            f"Open the admin's Builder tab and pick the columns.")
            else:
                out.update(ok=True, changed=True, sha=sha, rows=int(len(df)),
                           note=f"Pulled {fname} — {len(df)} rows.")
    except Exception as e:
        out["note"] = str(e)[:300]
        if prev.get("ok", True):        # tell a human once, not every retry
            _feed_alert(f"Catalog feed failed: {row['name']}",
                        f"The {kind} feed for \"{row['name']}\" failed:\n\n{out['note']}\n\n"
                        f"The catalog keeps serving its last good build. The feed retries "
                        f"on its schedule; this mail repeats only after it has recovered "
                        f"and broken again.")
    with eng.begin() as c:
        c.execute(text("update cat_sources set feed_status=:s where id=:i"),
                  {"s": json.dumps(out), "i": row["id"]})
    return out


def _feed_run_due(force_ids=None, customer=None) -> dict:
    """Run every due feed (or exactly force_ids), then rebuild each customer
    whose data actually changed — but only ones that have built at least once."""
    from sqlalchemy import text
    eng = _builder_engine()
    with eng.connect() as c:
        rows = c.execute(text("select * from cat_sources")).mappings().all()
    ran, touched = [], set()
    now = time.time()
    for r in rows:
        if customer is not None and r["customer"] != customer:
            continue
        cfg = _feed_of(r)
        kind = str(cfg.get("type") or "manual")
        if kind not in ("api", "sftp", "email"):
            continue
        if force_ids is not None:
            if r["id"] not in force_ids:
                continue
        else:
            every = max(1, min(int(cfg.get("every_hours") or 24), 168))
            if now - float(_feed_status_of(r).get("last_ts") or 0) < every * 3600:
                continue
        out = _feed_run_source(eng, r)
        ran.append({"id": r["id"], "name": r["name"], "ok": out.get("ok"),
                    "changed": out.get("changed"), "rows": out.get("rows"),
                    "note": out.get("note")})
        if out.get("changed"):
            touched.add(r["customer"])
    rebuilt = {}
    for cust in touched:
        with eng.connect() as c:
            if c.execute(text("select 1 from cat_built where customer=:c"),
                         {"c": cust}).first() is None:
                continue          # never built by hand yet — the admin goes first
        try:
            total, _per = _builder_do_build(eng, cust)
            rebuilt[cust] = total
        except Exception as e:
            rebuilt[cust] = f"not rebuilt: {e}"
            _feed_alert("Catalog not rebuilt",
                        f"A feed brought new data for \"{cust}\", but the catalog could not "
                        f"be rebuilt:\n\n{e}\n\nThe storefront keeps serving the last good "
                        f"build until this is fixed in the admin's Builder tab.")
    return {"ran": ran, "rebuilt": rebuilt}


async def _feed_loop():
    await asyncio.sleep(45)
    while True:
        try:
            if os.environ.get("CATALOG_DATABASE_URL", "").strip():
                await asyncio.to_thread(_feed_run_due)
        except Exception:
            pass
        await asyncio.sleep(15 * 60)


@app.on_event("startup")
async def _feed_start():
    asyncio.create_task(_feed_loop())


def _feed_public(cfg: dict) -> dict:
    out = dict(cfg or {})
    for k in ("password", "auth_pass", "client_secret"):
        if out.get(k):
            out[k] = _PW_KEPT
    return out


@app.post("/api/admin/builder/feed")
async def builder_feed_save(request: Request):
    sc, cust, _label = await _builder_admin(request)
    body = await request.json() or {}
    sid = str(body.get("id") or "")
    cfg = body.get("feed") or {}
    if not isinstance(cfg, dict):
        raise HTTPException(400, "Bad feed.")
    kind = str(cfg.get("type") or "manual").lower()
    if kind not in _FEED_TYPES:
        raise HTTPException(400, "Feed type must be manual, api, sftp or email.")
    from sqlalchemy import text
    eng = _builder_engine()
    with eng.begin() as c:
        row = c.execute(text("select * from cat_sources where id=:i and customer=:c"),
                        {"i": sid, "c": cust}).mappings().first()
        if not row:
            raise HTTPException(404, "No such source.")
        old = _feed_of(row)
        keep = {"type": kind}
        if kind == "api":
            keep["url"] = str(cfg.get("url") or "").strip()
            keep["header"] = str(cfg.get("header") or "").strip()
            keep["auth_user"] = str(cfg.get("auth_user") or "").strip()
            ap = str(cfg.get("auth_pass") or "")
            keep["auth_pass"] = old.get("auth_pass", "") if ap == _PW_KEPT else ap
            keep["qparams"] = [[str(k)[:80], str(v)[:300]]
                               for k, v in (cfg.get("qparams") or [])
                               if str(k).strip()][:20]
            keep["token_url"] = str(cfg.get("token_url") or "").strip()
            keep["client_id"] = str(cfg.get("client_id") or "").strip()
            cs = str(cfg.get("client_secret") or "")
            keep["client_secret"] = old.get("client_secret", "") if cs == _PW_KEPT else cs
        elif kind == "sftp":
            keep["host"] = str(cfg.get("host") or "").strip()
            try:
                keep["port"] = int(cfg.get("port") or 22)
            except Exception:
                keep["port"] = 22
            keep["user"] = str(cfg.get("user") or "").strip()
            pw = str(cfg.get("password") or "")
            keep["password"] = old.get("password", "") if pw == _PW_KEPT else pw
            keep["path"] = str(cfg.get("path") or "/").strip()
            keep["pattern"] = str(cfg.get("pattern") or "*").strip()
        elif kind == "email":
            keep["from_contains"] = str(cfg.get("from_contains") or "").strip()
            keep["subject_contains"] = str(cfg.get("subject_contains") or "").strip()
        if kind != "manual":
            try:
                keep["every_hours"] = max(1, min(int(cfg.get("every_hours") or 24), 168))
            except Exception:
                keep["every_hours"] = 24
        c.execute(text("update cat_sources set feed=:f where id=:i"),
                  {"f": json.dumps({} if kind == "manual" else keep), "i": sid})
    return {"ok": True}


@app.post("/api/admin/builder/feed/run")
async def builder_feed_run(request: Request):
    """Kick the pull off in the background and answer at once — a big API can
    take minutes, far past what a browser request survives. The card's status
    line updates itself when the pull lands."""
    sc, cust, _label = await _builder_admin(request)
    body = await request.json() or {}
    sid = str(body.get("id") or "")
    from sqlalchemy import text
    with _builder_engine().connect() as c:
        row = c.execute(text("select feed from cat_sources where id=:i and customer=:c"),
                        {"i": sid, "c": cust}).first()
    if row is None:
        raise HTTPException(404, "No such source.")
    try:
        kind = str((json.loads(row[0] or "{}") or {}).get("type") or "manual")
    except Exception:
        kind = "manual"
    if kind not in ("api", "sftp", "email"):
        raise HTTPException(400, "That source has no feed set up yet — pick one and save it first.")
    asyncio.create_task(asyncio.to_thread(_feed_run_due, {sid}, cust))
    return {"ok": True, "started": True,
            "message": "Checking — running in the background. A big API can take a few "
                       "minutes; the status line on the card updates when it finishes."}


# The static-file mount goes LAST: a mount at "/" catches every path, so every
# API route above must already be registered before it.
app.mount("/", StaticFiles(directory="static", html=True), name="static")
