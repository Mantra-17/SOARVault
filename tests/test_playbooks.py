"""
tests/test_playbooks.py
-----------------------
Unit tests for the playbook engine: risk scoring, playbook matching,
and trigger evaluation.
"""
import pytest
from ingestion.schema import NormalizedAlert, AlertType, Severity
from enrichment.risk_scorer import calculate_risk_score
from playbooks.engine import PlaybookEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    """Return a PlaybookEngine backed by fakeredis."""
    return PlaybookEngine()


@pytest.fixture
def brute_force_ctx():
    return {
        "risk_score": 90,
        "ioc_type": "ip",
        "severity": "critical",
    }


@pytest.fixture
def hash_ctx():
    return {
        "risk_score": 55,
        "ioc_type": "hash",
        "severity": "medium",
    }


# ---------------------------------------------------------------------------
# Risk Scoring Tests
# ---------------------------------------------------------------------------

class TestRiskScorer:
    def test_critical_with_full_enrichment(self):
        # Critical base (65) + Abuse score 90 (18) + VT malicious 68/72 (23) = 106 -> capped 100
        score = calculate_risk_score("critical", 90, "68/72")
        assert score == 100

    def test_low_no_enrichment(self):
        # Low base (10) + no enrichment = 10
        score = calculate_risk_score("low", None, None)
        assert score == 10

    def test_high_partial_enrichment(self):
        # High base (45) + Abuse score 50 (10) + VT malicious 36/72 (12) = 67
        score = calculate_risk_score("high", 50, "36/72")
        assert score == 67

    def test_score_capped_at_100(self):
        score = calculate_risk_score("critical", 100, "72/72")
        assert score <= 100

    def test_score_minimum_is_0(self):
        score = calculate_risk_score("low", 0, "0/72")
        assert score >= 0


# ---------------------------------------------------------------------------
# Playbook Matching Tests
# ---------------------------------------------------------------------------

class TestPlaybookEngine:
    def test_critical_ip_triggers_isolate(self, engine, brute_force_ctx):
        """Critical risk IP alert should trigger isolate-ec2-and-block-ip."""
        pb = engine.select_playbook(brute_force_ctx)
        assert pb is not None
        assert pb["id"] == "isolate-ec2-and-block-ip"

    def test_medium_hash_triggers_quarantine(self, engine, hash_ctx):
        """Medium risk hash alert should trigger quarantine-endpoint."""
        pb = engine.select_playbook(hash_ctx)
        assert pb is not None
        assert pb["id"] == "quarantine-endpoint"

    def test_low_risk_no_playbook(self, engine):
        """Low risk score should not match any playbook."""
        ctx = {"risk_score": 10, "ioc_type": "ip", "severity": "low"}
        pb = engine.select_playbook(ctx)
        assert pb is None

    def test_list_playbooks_returns_defaults(self, engine):
        """Engine should always return at least the 3 seeded playbooks."""
        playbooks = engine.list_playbooks()
        ids = [p["id"] for p in playbooks]
        assert "isolate-ec2-and-block-ip" in ids
        assert "block-ip-firewall" in ids
        assert "quarantine-endpoint" in ids

    def test_trigger_evaluation_safe(self, engine):
        """Trigger evaluator should reject invalid expressions gracefully."""
        # Valid trigger
        assert engine.evaluate_trigger(
            "risk_score >= 80 and ioc_type == 'ip'",
            {"risk_score": 90, "ioc_type": "ip", "severity": "critical"}
        ) is True

        # False condition
        assert engine.evaluate_trigger(
            "risk_score >= 80 and ioc_type == 'ip'",
            {"risk_score": 30, "ioc_type": "ip", "severity": "low"}
        ) is False

        # Malformed expression returns False without crashing
        assert engine.evaluate_trigger(
            "INVALID SYNTAX !!!", {}
        ) is False
