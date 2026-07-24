import os
import redis
import fakeredis

_client = None
_server = None

def get_redis_client():
    """
    Returns a Redis client instance.
    Tries to connect to a real Redis server first (env REDIS_URL or localhost).
    Falls back to a shared in-memory FakeRedis database (fakeredis) if connection fails.
    """
    global _client, _server
    if _client is not None:
        return _client

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    try:
        # Attempt to connect to real Redis
        client = redis.Redis.from_url(redis_url, decode_responses=True)
        client.ping()
        _client = client
        print(f"[*] Connected to Redis at {redis_url}")
    except Exception as e:
        print(f"[*] Redis connection failed: {e}. Falling back to in-memory fakeredis.")
        if _server is None:
            _server = fakeredis.FakeServer()
        _client = fakeredis.FakeRedis(server=_server, decode_responses=True)
    
    return _client
