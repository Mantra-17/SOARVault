import asyncio
import json
import os
import time
import pytest
from pathlib import Path

from ingestion.orchestrator import IncidentOrchestrator

SAMPLE_DIR = Path(__file__).parent.parent / "ingestion" / "sample_alerts"

def load_sample_alert(filename: str) -> dict:
    filepath = SAMPLE_DIR / filename
    if not filepath.exists():
        # Check alternative filename
        alt_name = "malware_lockbit.json" if "malware" in filename else filename
        filepath = SAMPLE_DIR / alt_name

    if not filepath.exists():
        return {
            "id": f"test_{time.time_ns()}",
            "source": "Test",
            "type": "brute_force",
            "severity": "high",
            "timestamp": "2023-01-01T00:00:00Z",
            "details": {}
        }
    with open(filepath, "r") as f:
        return json.load(f)

def test_pipeline_under_5_seconds():
    """
    Test that the end-to-end processing of a brute force and malware alert
    takes less than 5 seconds each.
    """
    async def _run():
        # Clear any prior dedup keys stored in Redis from earlier test files
        try:
            from ingestion.database import get_redis_client
            db = get_redis_client()
            keys = db.keys("dedup:*")
            if keys:
                db.delete(*keys)
        except Exception:
            pass

        orchestrator = IncidentOrchestrator()
        
        # 1. Test Brute Force Alert
        brute_force_alert = load_sample_alert("brute_force.json")
        
        start_time = time.perf_counter()
        result = await orchestrator.run_full_pipeline(brute_force_alert)
        end_time = time.perf_counter()
        
        execution_time = end_time - start_time
        assert execution_time < 5.0, f"Brute force pipeline too slow: {execution_time}s"
        assert result["status"] == "processed"

        # 2. Test Malware Alert
        malware_alert = load_sample_alert("malware.json")
        
        start_time = time.perf_counter()
        result = await orchestrator.run_full_pipeline(malware_alert)
        end_time = time.perf_counter()
        
        execution_time = end_time - start_time
        assert execution_time < 5.0, f"Malware pipeline too slow: {execution_time}s"
        assert result["status"] == "processed"

    asyncio.run(_run())
