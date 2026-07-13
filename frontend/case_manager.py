"""
case_manager.py — Incident case lifecycle helper

A "case" is opened automatically when the SOAR engine ingests an alert
that crosses the risk-score threshold. This module is a placeholder
the frontend can call against until the real enrichment/orchestration
engine (teammates' side) is ready. Swap MOCK_CASES for a real DB later.
"""

from datetime import datetime, timedelta
import itertools

_id_counter = itertools.count(1001)

MOCK_CASES = [
    {
        "id": "CASE-1001",
        "title": "Suspicious outbound traffic to known C2 IP",
        "severity": "critical",
        "status": "contained",
        "ioc": "185.220.101.7",
        "ioc_type": "ip",
        "risk_score": 92,
        "mttr_seconds": 3.8,
        "opened_at": (datetime.utcnow() - timedelta(minutes=14)).isoformat(),
        "playbook": "isolate-ec2-and-block-ip",
        "enrichment": {
            "abuseipdb_confidence": 97,
            "virustotal_malicious_votes": "41/89",
            "geo": "Bucharest, RO",
            "asn": "AS9009 (M247 Europe SRL)",
            "first_seen_in_feeds": "2024-02-11",
        },
        "timeline": [
            {"step": "Ingested", "detail": "Received from Splunk SIEM", "offset_seconds": 0},
            {"step": "Enriched", "detail": "AbuseIPDB + VirusTotal lookups completed", "offset_seconds": 0.6},
            {"step": "Risk Scored", "detail": "Composite score 92/100 — critical threshold", "offset_seconds": 1.1},
            {"step": "Playbook Triggered", "detail": "isolate-ec2-and-block-ip selected", "offset_seconds": 1.3},
            {"step": "Contained", "detail": "EC2 security group quarantined, IP blocked at edge firewall", "offset_seconds": 3.8},
        ],
    },
    {
        "id": "CASE-1002",
        "title": "Credential-stuffing pattern on VPN gateway",
        "severity": "high",
        "status": "in_progress",
        "ioc": "45.83.64.22",
        "ioc_type": "ip",
        "risk_score": 78,
        "mttr_seconds": None,
        "opened_at": (datetime.utcnow() - timedelta(minutes=3)).isoformat(),
        "playbook": "block-ip-firewall",
        "enrichment": {
            "abuseipdb_confidence": 81,
            "virustotal_malicious_votes": "12/89",
            "geo": "Frankfurt, DE",
            "asn": "AS24940 (Hetzner Online)",
            "first_seen_in_feeds": "2025-11-02",
        },
        "timeline": [
            {"step": "Ingested", "detail": "Received from QRadar SIEM", "offset_seconds": 0},
            {"step": "Enriched", "detail": "AbuseIPDB + VirusTotal lookups completed", "offset_seconds": 0.5},
            {"step": "Risk Scored", "detail": "Composite score 78/100 — high threshold", "offset_seconds": 0.9},
            {"step": "Playbook Triggered", "detail": "block-ip-firewall selected, awaiting firewall API ack", "offset_seconds": 1.2},
        ],
    },
    {
        "id": "CASE-1003",
        "title": "Malicious hash matched on endpoint (AbuseIPDB/VT)",
        "severity": "medium",
        "status": "resolved_auto",
        "ioc": "d41d8cd98f00b204e9800998ecf8427e",
        "ioc_type": "hash",
        "risk_score": 55,
        "mttr_seconds": 4.6,
        "opened_at": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
        "playbook": "quarantine-endpoint",
        "enrichment": {
            "abuseipdb_confidence": None,
            "virustotal_malicious_votes": "9/72",
            "geo": None,
            "asn": None,
            "first_seen_in_feeds": "2025-06-30",
        },
        "timeline": [
            {"step": "Ingested", "detail": "Received from CrowdStrike EDR", "offset_seconds": 0},
            {"step": "Enriched", "detail": "VirusTotal hash lookup completed", "offset_seconds": 0.7},
            {"step": "Risk Scored", "detail": "Composite score 55/100 — medium threshold", "offset_seconds": 1.4},
            {"step": "Playbook Triggered", "detail": "quarantine-endpoint selected", "offset_seconds": 1.6},
            {"step": "Contained", "detail": "Endpoint isolated via EDR API, no analyst action required", "offset_seconds": 4.6},
        ],
    },
]


def list_cases():
    return MOCK_CASES


def get_case(case_id: str):
    return next((c for c in MOCK_CASES if c["id"] == case_id), None)


def open_case(title, severity, ioc, risk_score, playbook):
    new_id = f"CASE-{next(_id_counter)}"
    case = {
        "id": new_id,
        "title": title,
        "severity": severity,
        "status": "in_progress",
        "ioc": ioc,
        "risk_score": risk_score,
        "mttr_seconds": None,
        "opened_at": datetime.utcnow().isoformat(),
        "playbook": playbook,
    }
    MOCK_CASES.insert(0, case)
    return case
