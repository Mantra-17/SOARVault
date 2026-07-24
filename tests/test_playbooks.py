import pytest
from ingestion.schema import RawAlert
from ingestion.normalizer import normalize_alert
from enrichment.risk_scorer import calculate_risk_score
from playbooks.engine import PlaybookEngine

def test_normalization():
    raw = RawAlert(
        source="Splunk SIEM",
        rule_name="Outbound connection to Tor exit node",
        severity="critical",
        ioc_type="ip",
        ioc_value="1.2.3.4"
    )
    normalized = normalize_alert(raw)
    assert normalized.source == "Splunk SIEM"
    assert normalized.severity == "critical"
    assert normalized.ioc_type == "ip"
    assert normalized.ioc_value == "1.2.3.4"
    assert normalized.enrichment_status == "queued"

def test_risk_scoring():
    # Critical base (65) + Abuse score 90 (18) + VT malicious 68/72 (23) = 100 (capped)
    score = calculate_risk_score("critical", 90, "68/72")
    assert score == 100
    
    # Low base (10) + no enrichment = 10
    score = calculate_risk_score("low", None, None)
    assert score == 10
    
    # High base (45) + Abuse score 50 (10) + VT malicious 36/72 (12) = 67
    score = calculate_risk_score("high", 50, "36/72")
    assert score == 67

def test_playbook_matching():
    engine = PlaybookEngine()
    
    # Match critical IP alert (should trigger isolate-ec2-and-block-ip)
    alert_ctx = {
        "risk_score": 90,
        "ioc_type": "ip",
        "severity": "critical"
    }
    pb = engine.select_playbook(alert_ctx)
    assert pb is not None
    assert pb["id"] == "isolate-ec2-and-block-ip"
    
    # Match medium hash alert (should trigger quarantine-endpoint)
    alert_ctx = {
        "risk_score": 55,
        "ioc_type": "hash",
        "severity": "medium"
    }
    pb = engine.select_playbook(alert_ctx)
    assert pb is not None
    assert pb["id"] == "quarantine-endpoint"
