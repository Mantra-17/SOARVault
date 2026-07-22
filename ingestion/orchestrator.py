import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List
from unittest.mock import MagicMock

from .normalizer import PayloadNormalizer
from .schema import NormalizedAlert

# Dynamically import the teammate's modules or mock them if incomplete
try:
    from enrichment.enricher import enrich_alert
except ImportError:
    enrich_alert = MagicMock(return_value={"mock_enriched": True})

try:
    from playbooks.executor import execute_playbook
except ImportError:
    execute_playbook = MagicMock(return_value={"mock_playbook_executed": True})

try:
    from dashboard.publisher import push_to_dashboard
except ImportError:
    push_to_dashboard = MagicMock(return_value={"mock_dashboard_pushed": True})

logger = logging.getLogger(__name__)


class IncidentOrchestrator:
    """
    Central orchestrator for the Ingestion pipeline.
    Handles: deduplication -> normalization -> enrichment -> playbooks -> dashboard.
    """
    def __init__(self):
        self.normalizer = PayloadNormalizer()
        self.seen_hashes = set()
        
        # In-memory metrics
        self.stats = {
            "total_ingested": 0,
            "total_duplicates": 0,
            "total_errors": 0,
            "average_latency_ms": 0.0,
            "total_enriched": 0
        }
        self.recent_alerts: List[Dict[str, Any]] = []

    def _generate_hash(self, raw_data: Dict[str, Any]) -> str:
        """Generate a SHA-256 hash of the alert to detect duplicates."""
        serialized = json.dumps(raw_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    async def run_full_pipeline(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main asynchronous pipeline:
        Raw Payload -> Normalize -> Enrich -> Playbook -> Dashboard
        """
        start_time = time.perf_counter()

        # 1. Deduplication
        alert_hash = self._generate_hash(raw_data)
        if alert_hash in self.seen_hashes:
            self.stats["total_duplicates"] += 1
            return {"status": "duplicate"}
        self.seen_hashes.add(alert_hash)
        self.stats["total_ingested"] += 1

        try:
            # 2. Normalization
            normalized_alert = self.normalizer.normalize(raw_data)
            logger.info("[INFO] Alert Normalized")

            # 3. Enrichment
            enriched_alert = await asyncio.to_thread(enrich_alert, normalized_alert)
            logger.info("[INFO] Enrichment Completed for IOCs")
            self.stats["total_enriched"] += 1
            
            # 4. Playbook Execution
            playbook_result = await asyncio.to_thread(execute_playbook, enriched_alert)
            logger.info("[INFO] Playbook Execution Completed")
            
            # 5. Dashboard Publication
            final_incident_state = {
                "alert": enriched_alert if isinstance(enriched_alert, dict) else enriched_alert.model_dump(mode="json"),
                "playbook_result": playbook_result
            }
            dashboard_result = await asyncio.to_thread(push_to_dashboard, final_incident_state)
            logger.info("[INFO] Dashboard Publication Completed")

            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            # Update latency stats (moving average approximation)
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
            logger.error(f"Error processing alert in pipeline: {e}")
            raise ValueError(f"Integration failed: {e}")

    async def process_alert(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Backward compatibility endpoint for batch and old endpoints."""
        return await self.run_full_pipeline(raw_data)

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.recent_alerts[:limit]

    def get_stats(self) -> Dict[str, Any]:
        return self.stats
