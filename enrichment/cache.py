"""
In-memory TTL caching module for threat intelligence enrichment lookups.
Prevents duplicate API calls within specified time windows (e.g. 1 hour).
"""

import time
from typing import Dict, Any, Optional, Tuple

# Storage for cached responses: {ip: (data_dict, expiration_timestamp)}
_CACHE: Dict[str, Tuple[Dict[str, Any], float]] = {}


def cache_response(ip: str, data: Dict[str, Any], ttl: int = 3600) -> None:
    """
    Cache a response for an IP address with a time-to-live (TTL) in seconds.
    Default TTL is 3600 seconds (1 hour).
    """
    expiration_time = time.time() + ttl
    _CACHE[ip] = (data, expiration_time)


def get_cached_response(ip: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve cached data for an IP address if present and not expired.
    Returns None if missing or expired.
    """
    if ip not in _CACHE:
        return None

    data, expiration_time = _CACHE[ip]
    if time.time() >= expiration_time:
        # Expired - remove from cache
        del _CACHE[ip]
        return None

    return data


def clear_cache() -> None:
    """
    Clear all entries from the in-memory cache.
    Useful for testing and manual resets.
    """
    _CACHE.clear()


def get_cache_size() -> int:
    """
    Get current number of active (non-expired) items in cache.
    """
    now = time.time()
    expired_keys = [k for k, (_, exp) in _CACHE.items() if now >= exp]
    for k in expired_keys:
        del _CACHE[k]
    return len(_CACHE)
