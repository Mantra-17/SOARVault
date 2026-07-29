"""Unit tests for the new features added to the SOARVault Enrichment Module.
Covers Days 12, 17, 18, 19, 23.
"""

import os
import json
import shutil
import pytest
from datetime import datetime, timezone

from enrichment.risk_scorer import calculate_risk_score, _COUNTRY_RISK
from enrichment.false_positive_detector import analyze_false_positive
from enrichment.mitre_mapper import MitreAttackMapper
from enrichment.threat_summary import generate_threat_report, REPORTS_DIR
from enrichment.batch_enricher import enrich_ips_concurrently


def test_configurable_country_risk_map(monkeypatch):
    """Verify country risk score can be overridden via environment variables (Day 12)."""
    # Verify standard behavior first
    assert _COUNTRY_RISK.get("RU") == 75
    assert _COUNTRY_RISK.get("KP") == 100
    assert _COUNTRY_RISK.get("IR") == 50
    assert _COUNTRY_RISK.get("US") is None

    # Change via environment variables
    monkeypatch.setenv("SOARVAULT_HIGHEST_RISK_COUNTRIES", "US")
    monkeypatch.setenv("SOARVAULT_HIGH_RISK_COUNTRIES", "FR,DE")
    monkeypatch.setenv("SOARVAULT_MEDIUM_RISK_COUNTRIES", "CA")

    assert _COUNTRY_RISK.get("US") == 100
    assert _COUNTRY_RISK.get("FR") == 75
    assert _COUNTRY_RISK.get("DE") == 75
    assert _COUNTRY_RISK.get("CA") == 50
    # KP should fall back to default when env is changed, or return None because US is the only highest
    assert _COUNTRY_RISK.get("KP") is None  # replaced by monkeypatch value


def test_false_positive_heuristics():
    """Verify false positive evaluation on public resolvers and trusted infrastructure (Day 18)."""
    # 1. Known public resolver
    is_fp, reason = analyze_false_positive("1.1.1.1", abuse_score=0, vt_malicious=0, vt_total=70, isp="Cloudflare")
    assert is_fp
    assert "public recursive DNS resolver" in reason

    # 2. Trusted ISP/Cloud Provider with clean scores
    is_fp, reason = analyze_false_positive("8.8.8.10", abuse_score=0, vt_malicious=0, vt_total=70, isp="Google LLC")
    assert is_fp
    assert "trusted infrastructure provider" in reason

    # 3. Malicious IP (not false positive)
    is_fp, reason = analyze_false_positive("192.168.1.100", abuse_score=100, vt_malicious=40, vt_total=70, isp="Unknown ISP")
    assert not is_fp
    assert reason == ""


def test_mitre_attack_mapping():
    """Verify mapping of alerts to MITRE ATT&CK techniques (Day 23)."""
    mapper = MitreAttackMapper()
    
    # 1. Exact match
    mapping = mapper.get_mapping("ssh_brute_force")
    assert mapping is not None
    assert mapping["technique_id"] == "T1110.001"
    assert mapping["tactic"] == "Credential Access"

    # 2. Fuzzy title match
    mapping = mapper.get_mapping("generic", title="Suspicious credential brute force attempts")
    assert mapping is not None
    assert mapping["technique_id"] == "T1110"

    # 3. Category heuristic match
    mapping = mapper.get_mapping("malware_alert", title="Outbound HTTPS connection detected")
    assert mapping is not None
    assert mapping["technique_id"] == "T1204.002" or "malware" in mapping["technique_name"].lower()  # Matches malware category


def test_threat_summary_generation():
    """Verify that threat summary JSON/MD reports are correctly written (Day 17)."""
    # Ensure reports dir is clear for this IP
    ip = "185.220.101.7"
    json_path = os.path.join(REPORTS_DIR, f"report_{ip}.json")
    md_path = os.path.join(REPORTS_DIR, f"report_{ip}.md")

    if os.path.exists(json_path):
        os.remove(json_path)
    if os.path.exists(md_path):
        os.remove(md_path)

    report = generate_threat_report(ip)
    
    assert report["ip"] == ip
    assert report["country"] == "Romania"
    assert report["isp"] == "M247 Europe SRL"
    assert report["final_risk_score"] > 0
    assert report["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert report["recommended_action"] != ""

    assert os.path.exists(json_path)
    assert os.path.exists(md_path)

    with open(json_path, "r", encoding="utf-8") as f:
        saved_data = json.load(f)
        assert saved_data["ip"] == ip


@pytest.mark.anyio
async def test_batch_enricher_concurrent():
    """Verify concurrent batch enrichment resolves multiple IPs (Day 19)."""
    # Clean offline execution using mocked demo IPs
    ips = ["185.220.101.7", "45.83.64.22", "203.0.113.55"]
    
    # Set offline mode
    os.environ["SOARVAULT_OFFLINE"] = "1"
    
    result = await enrich_ips_concurrently(ips)
    
    assert result["total_requested"] == 3
    assert result["successful"] == 3
    assert result["failed"] == 0
    
    # Check Romanians IP
    ro_res = result["results"]["185.220.101.7"]
    assert ro_res["country_code"] == "RO"
    assert ro_res["status"] == "success"
    
    # Check Germans IP
    de_res = result["results"]["45.83.64.22"]
    assert de_res["country_code"] == "DE"
    
    # Cleanup env
    os.environ.pop("SOARVAULT_OFFLINE", None)
