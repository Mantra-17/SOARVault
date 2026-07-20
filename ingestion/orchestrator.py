import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List

from .normalizer import PayloadNormalizer
from .schema import NormalizedAlert

# We will dynamically import the enrichment module in process_alert or at module level
# assuming it exists as enrichment.enricher.enrich_alert
try:
    from enrichment.enricher import enrich_alert
except ImportError:
    # Fallback if enrichment isn't available
    def enrich_alert(alert):
        return alert

logger = logging.getLogger(__name__)


class AlertOrchestrator:
    """
    Central orchestrator for the Ingestion pipeline.
    Handles: deduplication -> normalization -> enrichment -> (future) playbooks.
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
        # A simple stable serialization for hashing. We could limit this to specific fields
        # if the SIEM payload contains dynamic fields like "received_at" that change per webhook.
        # For this implementation, we'll hash the whole dictionary for simplicity.
        serialized = json.dumps(raw_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    async def process_alert(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main asynchronous pipeline:
        Raw Payload -> Deduplication -> Normalize -> Enrich
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
            normalized_alert: NormalizedAlert = self.normalizer.normalize(raw_data)

            # 3. Enrichment (Async wrapped)
            # The enrichment module might do synchronous network I/O, so we wrap it.
            enriched_alert = await asyncio.to_thread(enrich_alert, normalized_alert)
            self.stats["total_enriched"] += 1

            end_time = time.perf_counter()
            latency_ms = (end_time - start_time) * 1000

            # Update latency stats (moving average approximation)
            prev_avg = self.stats["average_latency_ms"]
            total = self.stats["total_enriched"]
            self.stats["average_latency_ms"] = prev_avg + (latency_ms - prev_avg) / total

            result = {
                "status": "processed",
                "pipeline_latency_ms": round(latency_ms, 2),
                "alert": enriched_alert.model_dump(mode="json")
            }

            # Store in recent memory (cap at 100)
            self.recent_alerts.insert(0, result)
            if len(self.recent_alerts) > 100:
                self.recent_alerts.pop()

            return result

        except Exception as e:
            self.stats["total_errors"] += 1
            logger.error(f"Error processing alert in pipeline: {e}")
            raise ValueError(f"Normalization or Enrichment failed: {e}")

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.recent_alerts[:limit]

    def get_stats(self) -> Dict[str, Any]:
        return self.stats
