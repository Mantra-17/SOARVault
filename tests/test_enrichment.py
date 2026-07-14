"""
Unit tests for enrichment modules: abuseipdb and geoip.
"""

import os
from unittest import mock
import pytest
import httpx

from enrichment.abuseipdb import query_ip
from enrichment.geoip import get_geolocation


# --- AbuseIPDB Tests ---

def test_query_ip_mock_specific_file():
    """Test that query_ip loads a specific mock file when requested."""
    # When IP contains the mock filename
    res = query_ip("abuseipdb_score_15")
    assert res["abuse_score"] == 15
    assert res["total_reports"] == 2
    assert res["country"] == "DE"
    assert res["isp"] == "Deutsche Telekom AG"
    assert res["last_reported_at"] == "2026-07-10T14:22:18+00:00"

    # When IP contains score 30
    res_30 = query_ip("192.168.1.30")
    assert res_30["abuse_score"] == 30

    # When IP contains score 100
    res_100 = query_ip("192.168.1.100")
    assert res_100["abuse_score"] == 100


def test_query_ip_mock_fallback_deterministic():
    """Test that query_ip falls back to stable hash for random IPs."""
    res_a = query_ip("8.8.8.8")
    res_b = query_ip("8.8.8.8")
    
    # Must be deterministic
    assert res_a == res_b
    assert "abuse_score" in res_a
    assert "total_reports" in res_a
    assert "country" in res_a
    assert "isp" in res_a
    assert "last_reported_at" in res_a


@mock.patch("enrichment.abuseipdb.ABUSEIPDB_API_KEY", "test-api-key")
@mock.patch("httpx.get")
def test_query_ip_real_api_success(mock_get):
    """Test that query_ip calls the real API when the key is available."""
    # Setup mock response from AbuseIPDB API v2
    mock_resp = mock.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "ipAddress": "118.25.6.39",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 100,
            "countryCode": "CN",
            "countryName": "China",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
            "domain": "tencent.com",
            "hostnames": [],
            "totalReports": 1,
            "numDistinctUsers": 1,
            "lastReportedAt": "2018-12-20T20:55:14+00:00"
        }
    }
    mock_get.return_value = mock_resp

    res = query_ip("118.25.6.39")
    
    # Verify mock call parameters
    mock_get.assert_called_once_with(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Accept": "application/json", "Key": "test-api-key"},
        params={"ipAddress": "118.25.6.39", "verbose": True}
    )
    
    # Verify mapping
    assert res == {
        "abuse_score": 100,
        "total_reports": 1,
        "country": "CN",
        "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
        "last_reported_at": "2018-12-20T20:55:14+00:00"
    }


# --- GeoIP Tests ---

@mock.patch("httpx.get")
def test_get_geolocation_success(mock_get):
    """Test that get_geolocation parses and returns a successful lookup from ip-api.com."""
    mock_resp = mock.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "region": "CA",
        "regionName": "California",
        "city": "Mountain View",
        "zip": "94043",
        "lat": 37.422,
        "lon": -122.084,
        "timezone": "America/Los_Angeles",
        "isp": "Google LLC",
        "org": "Google LLC",
        "as": "AS15169 Google LLC",
        "query": "8.8.8.8"
    }
    mock_get.return_value = mock_resp

    res = get_geolocation("8.8.8.8")
    
    mock_get.assert_called_once_with("http://ip-api.com/json/8.8.8.8", timeout=10.0)
    assert res == {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "Mountain View",
        "latitude": 37.422,
        "longitude": -122.084,
        "isp": "Google LLC",
        "org": "Google LLC",
        "asn": "AS15169 Google LLC",
        "timezone": "America/Los_Angeles"
    }


@mock.patch("httpx.get")
def test_get_geolocation_failure_status(mock_get):
    """Test that get_geolocation handles 'fail' status gracefully."""
    mock_resp = mock.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "fail",
        "message": "private range",
        "query": "10.0.0.1"
    }
    mock_get.return_value = mock_resp

    res = get_geolocation("10.0.0.1")
    assert res["country"] is None
    assert res["country_code"] is None
    assert res["error"] == "private range"


@mock.patch("httpx.get")
def test_get_geolocation_http_error(mock_get):
    """Test that get_geolocation handles HTTP client exception gracefully."""
    mock_get.side_effect = httpx.ConnectError("Connection timed out")

    res = get_geolocation("8.8.8.8")
    assert res["country"] is None
    assert "Connection timed out" in res["error"]
