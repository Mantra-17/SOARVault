"""
tests/conftest.py
-----------------
Shared Pytest fixtures for SOARVault test suite.
Provides fakeredis client, sample alert payloads, and mock context fixtures.
"""

import pytest
import fakeredis
from unittest import mock
from datetime import datetime, timezone
from ingestion.schema import NormalizedAlert, Severity, AlertType, AlertStatus, NetworkContext

@pytest.fixture
def fake_redis_db():
    """Returns a clean fakeredis instance for test isolation."""
    server = fakeredis.FakeServer()
    return fakeredis.FakeStrictRedis(server=server, decode_responses=True)

@pytest.fixture
def mock_sample_alert():
    """Returns a valid NormalizedAlert instance."""
    return NormalizedAlert(
        title="Suspicious Outbound Connection",
        type=AlertType.DATA_EXFIL,
        severity=Severity.HIGH,
        status=AlertStatus.NEW,
        detected_at=datetime.now(timezone.utc),
        network=NetworkContext(src_ip="192.168.1.50", dst_ip="185.220.101.7")
    )

@pytest.fixture
def mock_brute_force_payload():
    """Returns a raw brute force alert payload."""
    return {
        "title": "SSH Brute Force Attack Detected",
        "type": "brute_force",
        "severity": "high",
        "source": "Splunk SIEM",
        "timestamp": "2026-07-29T12:00:00Z",
        "network": {
            "src_ip": "185.234.218.20",
            "dst_ip": "10.0.0.5",
            "dst_port": 22
        }
    }
