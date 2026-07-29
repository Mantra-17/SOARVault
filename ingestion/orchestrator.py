"""
ingestion/orchestrator.py
--------------------------
Central orchestrator for the Ingestion pipeline.
Pipeline steps:
    1. Redis-backed Deduplication (TTL=3600s)
    2. Payload Normalization (PayloadNormalizer)
    3. Threat Intel Enrichment (enrich_alert)
    4. Playbook Execution (PlaybookEngine)
    5. Real-time Incident & Dashboard Publication (Redis case store)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional

from ingestion.database import get_redis_client
from ingestion.normalizer import PayloadNormalizer
from ingestion.schema import NormalizedAlert
from ingestion.audit import audit_logger

from enrichment.enricher import enrich_alert
from playbooks.engine import PlaybookEngine
from frontend.case_manager import create_case

logger = logging.getLogger(__name__)


def execute_playbook(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Selects and executes a playbook for an enriched alert using PlaybookEngine.
    """
    engine = PlaybookEngine()
    
    # 1. Convert to dictionary context if needed
    if isinstance(alert_data, NormalizedAlert):
        context = alert_data.to_summary()
        context["ioc_type"] = alert_data.ioc_type
        context["risk_score"] = alert_data.enrichment.risk_score if alert_data.enrichment else 0
        context["severity"] = alert_data.severity.value
    else:
        context = dict(alert_data)
        if "enrichment" in context and isinstance(context["enrichment"], dict):
            context["risk_score"] = context["enrichment"].get("risk_score", 0)

    # 2. Match playbook
    pb = engine.select_playbook(context)
    if not pb:
        return {
            "executed": False,
            "playbook": None,
            "message": "No matching playbook for alert context"
        }

    # 3. Create case and execute actions
    actions = pb.get("actions", [])
    case_id = create_case(context, actions)
    
    res = engine.execute(case_id, approved=False)
    res["playbook_id"] = pb.get("id")
    res["actions"] = actions
    return res


def push_to_dashboard(final_incident_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Publishes an incident to Redis store and updates metrics for real-time dashboard display.
    """
    db = get_redis_client()
    alert_info = final_incident_state.get("alert", {})
    pb_res = final_incident_state.get("playbook_result", {})

    try:
        # Update metrics counters
        db.incr("metrics:alerts_ingested_24h")
        if pb_res.get("executed") and pb_res.get("status") == "success":
            db.incr("metrics:cases_auto_contained_24h")

        # Publish incident event on Redis pub/sub channel for live UI updates
        payload = json.dumps(final_incident_state)
        db.publish("dashboard_updates", payload)
        return {"pushed": True, "channel": "dashboard_updates"}
    except Exception as e:
        logger.warning("Error pushing incident to dashboard: %s", e)
        return {"pushed": False, "error": str(e)}


class IncidentOrchestrator:
    """
    Central orchestrator for the Ingestion pipeline.
    Handles: deduplication -> normalization -> enrichment -> playbooks -> dashboard.
    """
    def __init__(self, source_siem: Optional[str] = None):
        self.normalizer = PayloadNormalizer(source_siem=source_siem)
        self.db = get_redis_client()

        # In-memory metrics tracking
        self.stats = {
            "total_ingested": 0,
            "total_duplicates": 0,
            "total_errors": 0,
            "average_latency_ms": 0.0,
            "total_enriched": 0
        }
        self.recent_alerts: List[Dict[str, Any]] = []

    def _generate_hash(self, raw_data: Dict[str, Any]) -> str:
        """Generate a SHA-256 hash of the alert payload to detect duplicates."""
        serialized = json.dumps(raw_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _is_duplicate(self, alert_hash: str) -> bool:
        """Redis-backed deduplication check with 1-hour TTL."""
        key = f"dedup:{alert_hash}"
        try:
            if self.db.exists(key):
                return True
            self.db.set(key, "1", ex=3600)
            return False
        except Exception:
            # Fallback to local memory if Redis unavailable
            return False

    async def run_full_pipeline(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main asynchronous pipeline:
        Raw Payload -> Deduplicate -> Normalize -> Enrich -> Playbook -> Dashboard
        """
        start_time = time.perf_counter()

        # 1. Deduplication (Redis-backed with TTL)
        alert_hash = self._generate_hash(raw_data)
        if self._is_duplicate(alert_hash):
            self.stats["total_duplicates"] += 1
            audit_logger.log_event("alert_duplicate", "orchestrator", {"alert_hash": alert_hash})
            return {"status": "duplicate", "alert_hash": alert_hash}

        self.stats["total_ingested"] += 1
        audit_logger.log_event("alert_ingested", "orchestrator", {"alert_hash": alert_hash})

        try:
            # 2. Normalization
            normalized_alert = self.normalizer.normalize(raw_data)
            logger.info("Alert Normalized id=%s", normalized_alert.alert_id)
            audit_logger.log_event(
                "alert_normalized",
                "normalizer",
                {"alert_id": str(normalized_alert.alert_id), "type": normalized_alert.type.value}
            )

            # 3. Enrichment
            enriched_alert = await asyncio.to_thread(enrich_alert, normalized_alert)
            logger.info("Enrichment Completed for alert id=%s", normalized_alert.alert_id)
            self.stats["total_enriched"] += 1

            # 4. Playbook Execution
            playbook_result = await asyncio.to_thread(execute_playbook, enriched_alert)
            logger.info("Playbook Execution Completed: %s", playbook_result)

            # 5. Dashboard Publication
            final_incident_state = {
                "alert": enriched_alert if isinstance(enriched_alert, dict) else enriched_alert.model_dump(mode="json"),
                "playbook_result": playbook_result
            }
            dashboard_result = await asyncio.to_thread(push_to_dashboard, final_incident_state)
            logger.info("Dashboard Publication Completed")

            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            # Update average latency
            prev_avg = self.stats["average_latency_ms"]
            total = self.stats["total_enriched"]
            self.stats["average_latency_ms"] = prev_avg + (latency_ms - prev_avg) / total

            result = {
                "status": "processed",
                "pipeline_latency_ms": round(latency_ms, 2),
                "final_incident_state": final_incident_state,
                "dashboard_result": dashboard_result
            }

            # Store in recent memory (cap at 100)
            self.recent_alerts.insert(0, result)
            if len(self.recent_alerts) > 100:
                self.recent_alerts.pop()

            return result

        except Exception as e:
            self.stats["total_errors"] += 1
            logger.error("Error processing alert in pipeline: %s", e)
            audit_logger.log_event("pipeline_error", "orchestrator", {"error": str(e)})
            raise ValueError(f"Integration failed: {e}")

    async def process_alert(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Backward compatibility entry point."""
        return await self.run_full_pipeline(raw_data)

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.recent_alerts[:limit]

    def get_stats(self) -> Dict[str, Any]:
        return self.stats
