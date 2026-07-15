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


# --- VirusTotal Tests ---

from enrichment.virustotal import check_hash, check_domain

def test_check_hash_mock_specific_file():
    """Test that check_hash loads a specific mock file when requested."""
    # When query contains specific name pattern (e.g., clean_1 or malicious_2)
    res_clean_1 = check_hash("virustotal_clean_1")
    assert res_clean_1["malicious_votes"] == 0
    assert res_clean_1["harmless_votes"] == 70
    assert res_clean_1["suspicious_votes"] == 0
    assert res_clean_1["verdict"] == "CLEAN"

    res_mal_2 = check_hash("malicious_2")
    assert res_mal_2["malicious_votes"] == 35
    assert res_mal_2["harmless_votes"] == 0
    assert res_mal_2["suspicious_votes"] == 2
    assert res_mal_2["verdict"] == "MALICIOUS"


def test_check_hash_mock_fallback_deterministic():
    """Test that check_hash falls back to stable hash for random inputs."""
    res_a = check_hash("some-random-file-hash-1")
    res_b = check_hash("some-random-file-hash-1")
    
    assert res_a == res_b
    assert "malicious_votes" in res_a
    assert "harmless_votes" in res_a
    assert "suspicious_votes" in res_a
    assert "verdict" in res_a


@mock.patch("enrichment.virustotal.VIRUSTOTAL_API_KEY", "test-api-key")
@mock.patch("httpx.get")
def test_check_hash_real_api_success(mock_get):
    """Test that check_hash calls the real API when the key is available."""
    mock_resp = mock.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "id": "mock-hash",
            "type": "file",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 45,
                    "malicious": 2,
                    "suspicious": 1
                }
            }
        }
    }
    mock_get.return_value = mock_resp

    res = check_hash("mock-hash")
    
    mock_get.assert_called_once_with(
        "https://www.virustotal.com/api/v3/files/mock-hash",
        headers={"accept": "application/json", "x-apikey": "test-api-key"}
    )
    
    assert res == {
        "malicious_votes": 2,
        "harmless_votes": 45,
        "suspicious_votes": 1,
        "verdict": "MALICIOUS"
    }


def test_check_domain_mock_specific_file():
    """Test that check_domain loads a specific mock file when requested."""
    res_clean_3 = check_domain("virustotal_clean_3")
    assert res_clean_3["malicious_votes"] == 0
    assert res_clean_3["harmless_votes"] == 62
    assert res_clean_3["suspicious_votes"] == 0
    assert res_clean_3["verdict"] == "CLEAN"


def test_check_domain_mock_fallback_deterministic():
    """Test that check_domain falls back to stable hash for random domains."""
    res_a = check_domain("google.com")
    res_b = check_domain("google.com")
    
    assert res_a == res_b
    assert "malicious_votes" in res_a
    assert "harmless_votes" in res_a
    assert "suspicious_votes" in res_a
    assert "verdict" in res_a


@mock.patch("enrichment.virustotal.VIRUSTOTAL_API_KEY", "test-api-key")
@mock.patch("httpx.get")
def test_check_domain_real_api_success(mock_get):
    """Test that check_domain calls the real API when the key is available."""
    mock_resp = mock.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "id": "example.com",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 80,
                    "malicious": 0,
                    "suspicious": 0
                }
            }
        }
    }
    mock_get.return_value = mock_resp

    res = check_domain("example.com")
    
    mock_get.assert_called_once_with(
        "https://www.virustotal.com/api/v3/domains/example.com",
        headers={"accept": "application/json", "x-apikey": "test-api-key"}
    )
    
    assert res == {
        "malicious_votes": 0,
        "harmless_votes": 80,
        "suspicious_votes": 0,
        "verdict": "CLEAN"
    }
