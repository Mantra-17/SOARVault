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

def clear_cache() -> None:
    """
    Flush all cached IoC enrichment entries.
    Used by test fixtures to ensure a clean state between test runs.
    """
    db = get_redis_client()
    try:
        keys = db.keys("cache:ioc:*")
        if keys:
            db.delete(*keys)
    except Exception as e:
        print(f"[*] Cache clear error: {e}")


def get_cached_response(ioc: str) -> dict or None:
    """Alias of get_cached_ioc — used by test_abuseipdb_real.py."""
    return get_cached_ioc(ioc)


def get_cache_size() -> int:
    """Return the number of IoC entries currently in cache."""
    db = get_redis_client()
    try:
        return len(db.keys("cache:ioc:*"))
    except Exception:
        return 0


# Alias: test_enrichment.py imports cache_response
cache_response = set_cached_ioc
