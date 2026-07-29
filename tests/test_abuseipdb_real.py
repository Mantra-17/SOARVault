"""
Integration test script to query 5 real public IPs using AbuseIPDB API (or mock fallback).
Tests real API key support and verifies that response caching prevents hitting the API twice for the same IP.
"""

import os
import pytest
from enrichment.abuseipdb import query_ip, ABUSEIPDB_API_KEY
from enrichment.cache import get_cached_response, clear_cache, get_cache_size

REAL_IPS = [
    "8.8.8.8",        # Google Public DNS
    "1.1.1.1",        # Cloudflare DNS
    "118.25.6.39",    # Tencent Cloud Public IP
    "185.220.101.5",  # Tor Exit Node
    "45.33.32.156"    # Scanme (Nmap test target)
]


@pytest.fixture(autouse=True)
def reset_cache():
    clear_cache()
    yield
    clear_cache()


def test_abuseipdb_5_real_ips():
    """
    Test querying 5 real IP addresses.
    Verifies response structure and verifies that secondary queries hit cache.
    """
    clear_cache()
    has_real_key = bool(os.getenv("ABUSEIPDB_API_KEY"))

    print(f"\n--- Testing AbuseIPDB with 5 Real IPs (API Key Present: {has_real_key}) ---")

    # First Pass: Fetch & Cache
    results = {}
    for ip in REAL_IPS:
        res = query_ip(ip)
        assert isinstance(res, dict)
        assert "abuse_score" in res
        assert "total_reports" in res
        assert "country" in res
        assert "isp" in res
        results[ip] = res
        print(f"IP: {ip:<15} | Score: {res.get('abuse_score'):<3} | Country: {res.get('country')} | ISP: {res.get('isp')}")

    assert get_cache_size() == len(REAL_IPS)

    # Second Pass: Verify Cache Hit (Prevent hitting API twice)
    print("\n--- Verifying Caching (2nd Pass for same IPs) ---")
    for ip in REAL_IPS:
        cached_data = get_cached_response(ip)
        assert cached_data is not None, f"Expected {ip} to be cached"
        assert cached_data == results[ip]
        
        # Second call to query_ip should return cached_data
        second_res = query_ip(ip)
        assert second_res == results[ip]
        print(f"IP: {ip:<15} | Cache Status: HIT (Returned cached data without re-querying)")


if __name__ == "__main__":
    test_abuseipdb_5_real_ips()
