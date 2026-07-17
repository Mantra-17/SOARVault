"""
Unit tests for enrichment modules: abuseipdb and geoip.
"""

import os
from datetime import datetime, timezone
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


# --- Risk Scorer Tests ---

from enrichment.risk_scorer import calculate_risk_score, get_risk_label
from ingestion.schema import EnrichmentData

def test_calculate_risk_score_dictionary():
    """Test calculate_risk_score with various dictionary configurations."""
    # 1. Low Risk Case
    data_low = {
        "abuse_score": 10,
        "vt_malicious": 0,
        "vt_total": 70,
        "geo_country_code": "US"
    }
    score = calculate_risk_score(data_low)
    assert score == 5
    assert get_risk_label(score) == "LOW"

    # 2. Medium Risk Case (with country risk)
    data_med = {
        "abuse_score": 50,
        "vt_malicious": 30,
        "vt_total": 60,
        "geo_country_code": "RU"
    }
    score = calculate_risk_score(data_med)
    # 50 * 0.5 + (30/60 * 100) * 0.3 + 100 * 0.2 = 25 + 15 + 20 = 60
    assert score == 60
    assert get_risk_label(score) == "MEDIUM"

    # 3. High Risk Case
    data_high = {
        "abuse_score": 80,
        "vt_malicious": 10,
        "vt_total": 10,
        "geo_country_code": "US"
    }
    score = calculate_risk_score(data_high)
    # 80 * 0.5 + (10/10 * 100) * 0.3 + 0 = 40 + 30 + 0 = 70
    assert score == 70
    assert get_risk_label(score) == "HIGH"

    # 4. Critical Risk Case
    data_crit = {
        "abuse_score": 90,
        "vt_malicious": 60,
        "vt_total": 70,
        "geo_country_code": "CN"
    }
    score = calculate_risk_score(data_crit)
    # 90 * 0.5 + (60/70 * 100) * 0.3 + 100 * 0.2 = 45 + 25.714 + 20 = 90.714 -> rounds to 91
    assert score == 91
    assert get_risk_label(score) == "CRITICAL"


def test_calculate_risk_score_pydantic():
    """Test calculate_risk_score with a Pydantic EnrichmentData object."""
    data = EnrichmentData(
        abuse_score=40,
        vt_malicious=5,
        vt_total=10,
        geo_country_code="RU"
    )
    score = calculate_risk_score(data)
    # 40 * 0.5 + (5/10 * 100) * 0.3 + 100 * 0.2 = 20 + 15 + 20 = 55
    assert score == 55
    assert get_risk_label(score) == "MEDIUM"


def test_calculate_risk_score_edge_cases():
    """Test risk scorer under various edge cases and missing fields."""
    # None input
    assert calculate_risk_score(None) == 0
    assert get_risk_label(0) == "LOW"

    # Empty dictionary
    assert calculate_risk_score({}) == 0

    # Missing vt_total, but vt_malicious > 0 (defaults to 70 total count)
    data_no_total = {
        "abuse_score": 80,
        "vt_malicious": 35,
        "geo_country_code": "US"
    }
    score = calculate_risk_score(data_no_total)
    # 80 * 0.5 + (35/70 * 100) * 0.3 + 0 = 40 + 15 + 0 = 55
    assert score == 55

    # Direct country_risk override
    data_override = {
        "abuse_score": 0,
        "vt_malicious": 0,
        "country_risk": 50
    }
    assert calculate_risk_score(data_override) == 10  # 50 * 0.2 = 10

    # Normalize country code input (lowercase, whitespace)
    data_country_norm = {
        "abuse_score": 0,
        "vt_malicious": 0,
        "country_code": "  cn  "
    }
    assert calculate_risk_score(data_country_norm) == 20  # 100 * 0.2 = 20


# --- Enricher Tests ---

from enrichment.enricher import enrich_alert
from ingestion.schema import NormalizedAlert, NetworkContext, IoC, Severity, AlertType, AlertStatus, EnrichmentData

@mock.patch("enrichment.enricher.query_ip")
@mock.patch("enrichment.enricher.get_geolocation")
@mock.patch("enrichment.enricher.check_domain")
@mock.patch("enrichment.enricher.check_hash")
def test_enrich_alert_dict(mock_check_hash, mock_check_domain, mock_get_geo, mock_query_ip):
    # Set up mock returns
    mock_query_ip.return_value = {
        "abuse_score": 40,
        "total_reports": 5,
        "country": "DE",
        "isp": "Test ISP",
        "last_reported_at": "2026-07-10T14:22:18+00:00"
    }
    mock_get_geo.return_value = {
        "country": "Germany",
        "country_code": "DE",
        "region": "Bavaria",
        "city": "Munich",
        "latitude": 48.1351,
        "longitude": 11.5820,
        "isp": "Test ISP",
        "org": "Test Org",
        "asn": "AS12345 Test ASN",
        "timezone": "Europe/Berlin"
    }
    mock_check_domain.return_value = {
        "malicious_votes": 2,
        "harmless_votes": 60,
        "suspicious_votes": 0,
        "verdict": "MALICIOUS"
    }
    mock_check_hash.return_value = {
        "malicious_votes": 5,
        "harmless_votes": 50,
        "suspicious_votes": 1,
        "verdict": "MALICIOUS"
    }

    # Define a dict-based alert
    alert_dict = {
        "title": "Brute Force Attempt",
        "severity": "medium",
        "status": "new",
        "network": {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5"
        },
        "iocs": [
            {"type": "domain", "value": "malicious.com"},
            {"type": "file_hash", "value": "a1b2c3d4e5f6"}
        ],
        "timeline": []
    }

    enriched = enrich_alert(alert_dict)

    # Assertions
    assert isinstance(enriched, dict)
    assert enriched["status"] == "triaged"
    
    # Check enrichment block
    enrich_data = enriched["enrichment"]
    assert enrich_data["abuse_score"] == 40
    assert enrich_data["vt_malicious"] == 7  # 2 + 5
    assert enrich_data["vt_total"] == 118   # (2+60+0) + (5+50+1)
    assert enrich_data["geo_country_code"] == "DE"
    assert enrich_data["geo_asn_org"] == "AS12345 Test ASN"
    
    # Calculated risk score check:
    # abuse_score = 40 (weight 0.5 -> 20)
    # vt_score: vt_malicious=7, vt_total=118 -> (7 / 118) * 100 = 5.9322% (weight 0.3 -> 1.7797)
    # country_risk_score = 0 (DE not in high risk, weight 0.2 -> 0)
    # Total = 20 + 1.78 = 21.78 -> rounds to 22
    assert enrich_data["risk_score"] == 22.0

    # Check network geo enrichment
    assert enriched["network"]["geo_country"] == "Germany"
    assert enriched["network"]["geo_city"] == "Munich"
    assert enriched["network"]["asn"] == "AS12345 Test ASN"

    # Check timeline
    assert len(enriched["timeline"]) == 1
    assert enriched["timeline"][0]["actor"] == "enrichment.enricher"
    assert enriched["timeline"][0]["action"] == "alert_enriched"


@mock.patch("enrichment.enricher.query_ip")
@mock.patch("enrichment.enricher.get_geolocation")
@mock.patch("enrichment.enricher.check_domain")
@mock.patch("enrichment.enricher.check_hash")
def test_enrich_alert_pydantic(mock_check_hash, mock_check_domain, mock_get_geo, mock_query_ip):
    # Set up mock returns
    mock_query_ip.return_value = {"abuse_score": 80}
    mock_get_geo.return_value = {
        "country": "Russian Federation",
        "country_code": "RU",
        "asn": "AS9999",
    }
    # No VT IoCs in this test alert
    
    # Define a Pydantic NormalizedAlert
    alert = NormalizedAlert(
        title="Suspicious Login",
        severity=Severity.HIGH,
        status=AlertStatus.NEW,
        detected_at=datetime.now(timezone.utc),
        network=NetworkContext(src_ip="95.165.1.1"),
        iocs=[]
    )

    enriched = enrich_alert(alert)

    # Assertions
    assert isinstance(enriched, NormalizedAlert)
    assert enriched.status == AlertStatus.TRIAGED
    
    # Check enrichment block
    assert enriched.enrichment is not None
    assert enriched.enrichment.abuse_score == 80
    assert enriched.enrichment.geo_country_code == "RU"
    # Calculated risk score check:
    # abuse_score = 80 (weight 0.5 -> 40)
    # vt_score = 0 (weight 0.3 -> 0)
    # country_risk_score = 100 (RU is high risk, weight 0.2 -> 20)
    # Total = 40 + 0 + 20 = 60
    assert enriched.enrichment.risk_score == 60.0

    # Check network geo enrichment
    assert enriched.network.geo_country == "Russian Federation"
    assert enriched.network.asn == "AS9999"

    # Check timeline
    assert len(enriched.timeline) == 1  # 1 from enricher
    assert enriched.timeline[-1]["actor"] == "enrichment.enricher"


@mock.patch("enrichment.enricher.query_ip")
@mock.patch("enrichment.enricher.get_geolocation")
@mock.patch("enrichment.enricher.check_domain")
@mock.patch("enrichment.enricher.check_hash")
def test_enrich_alert_error_handling(mock_check_hash, mock_check_domain, mock_get_geo, mock_query_ip):
    # Make queries raise errors
    mock_query_ip.side_effect = RuntimeError("AbuseIPDB service down")
    mock_get_geo.side_effect = Exception("GeoIP lookup timeout")
    mock_check_domain.side_effect = Exception("VT domain limit exceeded")
    mock_check_hash.return_value = {
        "malicious_votes": 10,
        "harmless_votes": 0,
        "suspicious_votes": 0,
        "verdict": "MALICIOUS"
    }

    alert_dict = {
        "title": "Malicious Hash Detected",
        "network": {"src_ip": "8.8.8.8"},
        "iocs": [
            {"type": "domain", "value": "broken-link.com"},
            {"type": "file_hash", "value": "deadbeef"}
        ]
    }

    # Should complete without raising exceptions
    enriched = enrich_alert(alert_dict)

    assert enriched["status"] == "triaged"
    enrich_data = enriched["enrichment"]
    
    # Check what succeeded
    assert enrich_data["vt_malicious"] == 10
    # Check what failed is None
    assert enrich_data["abuse_score"] is None
    assert enrich_data["geo_country_code"] is None
    # Calculated risk score check:
    # abuse_score = 0 (default fallback, weight 0.5 -> 0)
    # vt_score: 10 malicious, 10 total -> 100% (weight 0.3 -> 30)
    # country_risk_score = 0 (weight 0.2 -> 0)
    # Total = 30
    assert enrich_data["risk_score"] == 30.0


