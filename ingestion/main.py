import logging
from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .schema import NormalizedAlert
from .orchestrator import IncidentOrchestrator
from .audit import audit_logger

# Setup basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SOARVault Ingestion API",
    description="Webhook receiver and orchestration entrypoint for SIEM alerts.",
    version="1.0.0"
)

# Global Orchestrator instance
orchestrator = IncidentOrchestrator()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "error": str(exc)},
    )


@app.get(
    "/health",
    tags=["System"],
    summary="Readiness/Liveness probe",
    description="Check the health of the ingestion API service.",
    response_description="A JSON object containing the status of the service."
)
async def health_check():
    """Readiness/Liveness probe."""
    return {"status": "ok", "service": "ingestion-api"}


@app.post(
    "/webhook/alert",
    tags=["Ingestion"],
    summary="Ingest a single raw SIEM alert",
    description="Receives a raw SIEM payload, normalizes it, enriches it with threat intelligence, and triggers the appropriate SOAR playbook.",
    response_description="A JSON object detailing the processing result.",
    responses={
        200: {"description": "Alert processed successfully"},
        202: {"description": "Alert ignored (duplicate)"},
        422: {"description": "Validation error"}
    }
)
async def receive_alert(payload: Dict[str, Any]):
    """Ingest a single raw SIEM alert."""
    try:
        # Pass to the async orchestrator pipeline
        result = await orchestrator.run_full_pipeline(payload)
        if result.get("status") == "duplicate":
            return JSONResponse(status_code=202, content={"message": "Alert ignored (duplicate)."})
        return {"message": "Alert processed successfully.", "data": result}
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=str(ve))


@app.post(
    "/webhook/alerts/batch",
    tags=["Ingestion"],
    summary="High-throughput batch ingestion",
    description="Process multiple SIEM alerts in a single HTTP request for high-throughput scenarios.",
    response_description="Summary of the batch processing including processed, duplicate, and error counts."
)
async def receive_alerts_batch(payloads: List[Dict[str, Any]]):
    """High-throughput batch ingestion."""
    processed = 0
    duplicates = 0
    errors = 0
    results = []

    for payload in payloads:
        try:
            result = await orchestrator.process_alert(payload)
            if result.get("status") == "duplicate":
                duplicates += 1
            else:
                processed += 1
                results.append(result)
        except Exception as e:
            logger.error(f"Error processing alert in batch: {e}")
            errors += 1

    return {
        "message": "Batch processed.",
        "processed": processed,
        "duplicates": duplicates,
        "errors": errors,
        "data": results
    }


@app.get(
    "/alerts",
    tags=["Query"],
    summary="Fetch recently processed alerts",
    description="Retrieve a list of recently processed and enriched alerts from the SOAR engine."
)
async def get_recent_alerts(limit: int = 50):
    """Fetch recently processed (and enriched) alerts."""
    return orchestrator.get_recent_alerts(limit=limit)


@app.get(
    "/stats",
    tags=["System"],
    summary="Return ingestion metrics",
    description="Fetch ingestion and orchestration statistics, including average latency and throughput."
)
async def get_stats():
    """Return ingestion and orchestration metrics."""
    return orchestrator.get_stats()


@app.get(
    "/audit-log",
    tags=["Audit"],
    summary="Fetch recent audit logs",
    description="Retrieve the structured audit log trail of playbook execution actions and playbook routing decisions."
)
async def get_audit_log(limit: int = 100):
    """Fetch recent structured audit logs."""
    return {"audit_logs": audit_logger.get_recent_logs(limit=limit)}
