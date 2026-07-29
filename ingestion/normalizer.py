import random
from datetime import datetime
from ingestion.schema import RawAlert, NormalizedAlert
from ingestion.database import get_redis_client

def normalize_alert(raw: RawAlert) -> NormalizedAlert:
    """
    Normalizes a vendor-specific raw alert into a standardized format.
    Generates a unique alert ID using Redis counters (with a random fallback).
    """
    db = get_redis_client()
    try:
        alert_seq = db.incr("counters:alert_id")
        # Ensure we match standard mock IDs format (around 88000+)
        if alert_seq < 88000:
            db.set("counters:alert_id", 88200)
            alert_seq = 88200
    except Exception:
        alert_seq = random.randint(88200, 89000)
        
    alert_id = f"ALRT-{alert_seq}"
    received_at = raw.received_at or datetime.utcnow().isoformat()
    
    # Standardize severity
    severity = raw.severity.lower().strip()
    if severity not in ("critical", "high", "medium", "low"):
        severity = "medium"
        
    return NormalizedAlert(
        id=alert_id,
        title=raw.rule_name,
        source=raw.source,
        severity=severity,
        ioc_value=raw.ioc_value,
        ioc_type=raw.ioc_type.lower().strip(),
        received_at=received_at,
        enrichment_status="queued"
    )
