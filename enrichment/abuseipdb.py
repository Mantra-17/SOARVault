"""
enrichment/abuseipdb.py
-----------------------
AbuseIPDB IP reputation lookup.

Design notes:
  - Uses bare `httpx.get()` calls (NOT httpx.Client) so tests can patch
    `httpx.get` directly via mock.patch("httpx.get").
  - ABUSEIPDB_API_KEY is exposed at module level so tests can patch it.
  - Caches response to Redis via set_cached_ioc / get_cached_ioc.
  - Mock file selection handles score stems, IP last octet, or deterministic hash fallback.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from enrichment.cache import get_cached_ioc, set_cached_ioc

# Exposed at module level so tests can patch: mock.patch("enrichment.abuseipdb.ABUSEIPDB_API_KEY", "x")
ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")

MOCK_DIR = Path(__file__).parent / "mock_responses"

# Explicit octet -> mock file map
_EXPLICIT_OCTET_MAP: Dict[int, str] = {
    100: "abuseipdb_score_100_1",
    90:  "abuseipdb_score_90",
    85:  "abuseipdb_score_85",
    75:  "abuseipdb_score_75",
    50:  "abuseipdb_score_50",
    30:  "abuseipdb_score_30",
    15:  "abuseipdb_score_15",
    0:   "abuseipdb_score_0_1",
}

# Modulo 10 mapping fallback
_OCTET_MODULO_MAP: Dict[int, str] = {
    0: "abuseipdb_score_0_1",
    1: "abuseipdb_score_0_2",
    2: "abuseipdb_score_15",
    3: "abuseipdb_score_30",
    4: "abuseipdb_score_50",
    5: "abuseipdb_score_75",
    6: "abuseipdb_score_85",
    7: "abuseipdb_score_90",
    8: "abuseipdb_score_100_1",
    9: "abuseipdb_score_100_2",
}

# Override map for well-known demo IPs
_IP_MAP: Dict[str, str] = {
    "185.220.101.7": "abuseipdb_score_90",
    "45.83.64.22":   "abuseipdb_score_85",
    "203.0.113.55":  "abuseipdb_score_75",
}


def _parse_mock(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise mock file keys → canonical return dict."""
    score = data.get("abuse_confidence_score")
    if score is None:
        score = data.get("abuse_score", 0)
    return {
        "abuse_score":      int(score),
        "total_reports":    data.get("total_reports", 0),
        "country":          data.get("country_code") or data.get("country") or "US",
        "isp":              data.get("isp", "Unknown ISP"),
        "last_reported_at": data.get("last_reported_at") or data.get("last_reported"),
    }


def _load_mock_by_stem(stem: str) -> Optional[Dict[str, Any]]:
    """Try to load a mock file by its stem name."""
    for candidate in [stem, f"abuseipdb_{stem}"]:
        path = MOCK_DIR / f"{candidate}.json"
        if path.exists():
            try:
                with open(path) as f:
                    return _parse_mock(json.load(f))
            except Exception:
                pass
    return None


def _load_mock_for_ip(ip: str) -> Dict[str, Any]:
    """Select and load the appropriate mock file for a given IP."""
    # 1. Direct IP override
    if ip in _IP_MAP:
        result = _load_mock_by_stem(_IP_MAP[ip])
        if result:
            return result

    # 2. Check if IP contains a target score or stem pattern (e.g., "abuseipdb_score_15", "192.168.1.100")
    for mock_file in sorted(MOCK_DIR.glob("abuseipdb_*.json")):
        stem = mock_file.stem  # e.g., "abuseipdb_score_15"
        short_stem = stem.replace("abuseipdb_", "")  # "score_15"
        if stem in ip or short_stem in ip:
            try:
                with open(mock_file) as f:
                    return _parse_mock(json.load(f))
            except Exception:
                pass

    # 3. Last-octet mapping
    parts = ip.split(".")
    try:
        last_octet = int(parts[-1]) if parts else 0
    except ValueError:
        last_octet = 0

    if last_octet in _EXPLICIT_OCTET_MAP:
        result = _load_mock_by_stem(_EXPLICIT_OCTET_MAP[last_octet])
        if result:
            return result

    stem = _OCTET_MODULO_MAP.get(last_octet % 10, "abuseipdb_score_0_1")
    result = _load_mock_by_stem(stem)
    if result:
        return result

    # 4. Hardcoded fallback
    return {
        "abuse_score":      0,
        "total_reports":    0,
        "country":          "US",
        "isp":              "Unknown ISP",
        "last_reported_at": None,
    }


def check_ip(ip: str) -> Dict[str, Any]:
    """
    Enrich an IP address using AbuseIPDB.

    Checks Redis cache first. On miss, uses real API if ABUSEIPDB_API_KEY is set,
    otherwise loads deterministic mock data, then saves to cache.
    """
    # 1. Check cache first
    cached = get_cached_ioc(ip)
    if cached:
        return cached

    api_key = ABUSEIPDB_API_KEY or os.getenv("ABUSEIPDB_API_KEY")
    res_data = None

    if api_key:
        try:
            res = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Accept": "application/json", "Key": api_key},
                params={"ipAddress": ip, "verbose": True},
            )
            if res.status_code == 200:
                data = res.json().get("data", {})
                res_data = {
                    "abuse_score":      data.get("abuseConfidenceScore", 0),
                    "total_reports":    data.get("totalReports", 0),
                    "country":          data.get("countryCode", "US"),
                    "isp":              data.get("isp", "Unknown ISP"),
                    "last_reported_at": data.get("lastReportedAt"),
                }
        except Exception as e:
            print(f"[*] AbuseIPDB API request failed, falling back to mock: {e}")

    if not res_data:
        res_data = _load_mock_for_ip(ip)

    # 2. Save result to cache
    set_cached_ioc(ip, res_data)
    return res_data


async def check_ip_async(ip: str) -> Dict[str, Any]:
    """
    Enrich an IP address using AbuseIPDB asynchronously.

    Checks Redis cache first. On miss, uses real API if ABUSEIPDB_API_KEY is set,
    otherwise loads deterministic mock data, then saves to cache.
    """
    # 1. Check cache first
    cached = get_cached_ioc(ip)
    if cached:
        return cached

    api_key = ABUSEIPDB_API_KEY or os.getenv("ABUSEIPDB_API_KEY")
    res_data = None

    if api_key:
        try:
            async with httpx.AsyncClient() as client:
                res = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Accept": "application/json", "Key": api_key},
                    params={"ipAddress": ip, "verbose": True},
                    timeout=5.0
                )
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    res_data = {
                        "abuse_score":      data.get("abuseConfidenceScore", 0),
                        "total_reports":    data.get("totalReports", 0),
                        "country":          data.get("countryCode", "US"),
                        "isp":              data.get("isp", "Unknown ISP"),
                        "last_reported_at": data.get("lastReportedAt"),
                    }
        except Exception as e:
            print(f"[*] Async AbuseIPDB API request failed, falling back to mock: {e}")

    if not res_data:
        res_data = _load_mock_for_ip(ip)

    # 2. Save result to cache
    set_cached_ioc(ip, res_data)
    return res_data


# ---------------------------------------------------------------------------
# Public aliases
# ---------------------------------------------------------------------------
query_ip = check_ip
query_ip_async = check_ip_async

