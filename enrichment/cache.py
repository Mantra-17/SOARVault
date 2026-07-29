import json
import time
from typing import Optional, Dict, Any
from ingestion.database import get_redis_client

def get_cached_ioc(ioc: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves cached IOC enrichment details from Redis.
    Respects time.time() based expiration for mock testing compatibility.
    """
    db = get_redis_client()
    try:
        val = db.get(f"cache:ioc:{ioc}")
        if val:
            parsed = json.loads(val)
            if isinstance(parsed, dict) and "_expires_at" in parsed:
                if time.time() > parsed["_expires_at"]:
                    db.delete(f"cache:ioc:{ioc}")
                    return None
                return parsed.get("data")
            return parsed
    except Exception as e:
        print(f"[*] Cache read error for {ioc}: {e}")
    return None

def set_cached_ioc(ioc: str, data: Dict[str, Any], ttl: int = 3600):
    """
    Caches IOC enrichment details in Redis with a TTL.
    """
    db = get_redis_client()
    try:
        payload = {
            "_expires_at": time.time() + ttl,
            "data": data
        }
        db.set(f"cache:ioc:{ioc}", json.dumps(payload), ex=ttl)
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


def get_cached_response(ioc: str) -> Optional[Dict[str, Any]]:
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
