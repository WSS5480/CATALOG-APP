# Catalog / Order Form app

A standalone web app. It stores no data — it connects to an **ETL Space**
instance and reads whichever datasets this copy is pointed at. Deploy as many
copies as you want, each aimed at different data (Pentex catalog, Ashley
catalog, a test catalog…), all sharing one ETL Space.

    ETL Space  (datasets, flows, connectors)
        ▲            ▲            ▲
        │            │            │
    Catalog app  Catalog app  Catalog app
     (Pentex)     (Ashley)      (test)

## Deploy on Render

**New → Web Service →** pick the `CATALOG-ETL-BUILD` repo, then set:

| Field | Value |
|---|---|
| Name | `catalog-pentex` (anything — becomes the URL) |
| Root Directory | `catalog-app` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn server:app --host 0.0.0.0 --port $PORT` |
| Instance Type | Free |

### Environment variables

| Key | What it does |
|---|---|
| `ETL_BASE_URL` | URL of your ETL Space, e.g. `https://catalog-etl.onrender.com` |
| `ETL_API_TOKEN` | The `API_TOKEN` you set on ETL Space (preferred) |
| `ETL_USER` / `ETL_PASSWORD` | Alternative to the token — ETL Space login |
| `DS_CATALOG` | Dataset name that holds products (required) |
| `DS_USERS` | Dataset name with districts / stores / managers |
| `DS_VENDORS` | Dataset name with vendors |
| `DS_FREIGHT` | Dataset name with freight per store (optional) |
| `ORDERS_COLLECTION` | Where orders are saved (default `OrderFormClaud`) |
| `APP_PASSWORD` | Optional password to open this app |

To point a second copy at different data, deploy it again with a different
`DS_CATALOG`. Nothing else changes.

## Run it on your computer

    set ETL_BASE_URL=https://your-etl-space.onrender.com
    set ETL_API_TOKEN=your-token
    set DS_CATALOG=pentex_master
    pip install -r requirements.txt
    uvicorn server:app --port 8090

Then open http://localhost:8090

## Check the connection

`GET /healthz` reports whether the connector is configured, and
`GET /api/app/config` shows which datasets this copy is using.
