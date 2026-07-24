import json
from ingestion.database import get_redis_client

def get_cached_ioc(ioc: str) -> dict or None:
    """
    Retrieves cached IOC enrichment details from Redis.
    """
    db = get_redis_client()
    try:
        val = db.get(f"cache:ioc:{ioc}")
        if val:
            return json.loads(val)
    except Exception as e:
        print(f"[*] Cache read error for {ioc}: {e}")
    return None

def set_cached_ioc(ioc: str, data: dict, ttl: int = 3600):
    """
    Caches IOC enrichment details in Redis with a TTL.
    """
    db = get_redis_client()
    try:
        db.setex(f"cache:ioc:{ioc}", ttl, json.dumps(data))
    except Exception as e:
        print(f"[*] Cache write error for {ioc}: {e}")
