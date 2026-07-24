# SOARVault Ingestion API

The Ingestion API is built with FastAPI and provides endpoints for receiving raw SIEM payloads, querying processed alerts, and fetching audit logs.

## OpenAPI (Swagger) Documentation

Because this API is built using FastAPI, interactive and comprehensive documentation is automatically generated and served by the application.

* **Swagger UI:** `http://localhost:8000/docs`
* **ReDoc:** `http://localhost:8000/redoc`
* **Raw OpenAPI JSON:** `http://localhost:8000/openapi.json`

## Key Endpoints

### `POST /webhook/alert`
Receives a single raw SIEM alert. The payload is normalized, enriched asynchronously, and passed to the playbook engine.

### `POST /webhook/alerts/batch`
High-throughput ingestion endpoint for processing an array of raw alerts in parallel.

### `GET /alerts`
Fetches a list of recently processed alerts, including their current status and risk score.

### `GET /audit-log`
Fetches the structured audit log trail representing all automated playbook containment actions and routing decisions made by the orchestrator.

### `GET /stats`
Returns ingestion metrics, including average latency, processing counts, and deduplication statistics.
