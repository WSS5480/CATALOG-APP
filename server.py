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
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

ETL_BASE = os.environ.get("ETL_BASE_URL", "").rstrip("/")
ETL_USER = os.environ.get("ETL_USER", "app")
ETL_PASSWORD = os.environ.get("ETL_PASSWORD", "")
ETL_TOKEN = os.environ.get("ETL_API_TOKEN", "")
ORDERS_COLLECTION = os.environ.get("ORDERS_COLLECTION", "OrderFormClaud")

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


async def etl_get(path: str, params: dict | None = None):
    _require_config()
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.get(f"{ETL_BASE}{path}", params=params or {}, **_etl_auth())
    if r.status_code >= 400:
        raise HTTPException(r.status_code, f"ETL Space: {r.text[:300]}")
    return r.json()


async def etl_send(method: str, path: str, payload=None):
    _require_config()
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.request(method, f"{ETL_BASE}{path}", json=payload, **_etl_auth())
    if r.status_code >= 400:
        raise HTTPException(r.status_code, f"ETL Space: {r.text[:300]}")
    try:
        return r.json()
    except Exception:
        return {"ok": True}


# ---------------- config the app UI can read ----------------

@app.get("/api/app/config")
async def app_config():
    return {"etl": ETL_BASE, "datasets": DATASETS, "orders": ORDERS_COLLECTION,
            "configured": bool(ETL_BASE and DATASETS["catalog"])}


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
    ds = _dataset_for(ident)
    if not ds:
        raise HTTPException(400, "This app has no dataset configured for that request. "
                                 "Set DS_CATALOG / DS_USERS / DS_VENDORS.")
    return await etl_send("POST", f"/api/app/query/{ds}", {"sql": body.get("sql", ""),
                                                           "dataset": ds})


@app.get("/api/app/rows/{ident}")
async def rows(ident: str, request: Request):
    ds = _dataset_for(ident)
    if not ds:
        raise HTTPException(400, "No dataset configured for that request.")
    params = dict(request.query_params)
    params["dataset"] = ds
    return await etl_get(f"/api/app/rows/{ds}", params)


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


app.mount("/", StaticFiles(directory="static", html=True), name="static")
