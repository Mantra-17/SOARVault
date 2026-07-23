"""
case_manager.py — in-memory incident case store.

Public API (per checklist):
  create_case(alert, actions)              -> case_id
  get_case(case_id)                        -> dict | None
  list_cases(limit=50, severity=None)      -> list[dict]
  update_case_status(case_id, status)      -> bool

A "case" is opened when the orchestration engine decides to act on an
enriched alert. `alert` is the enriched alert dict (title, severity,
ioc, ioc_type, risk_score, etc.) and `actions` is the ordered list of
containment actions the matched playbook is running. This is an
in-memory placeholder — swap for a real DB once persistence is needed.
"""

from datetime import datetime, timedelta
import itertools

_id_counter = itertools.count(1001)
_CASES: dict[str, dict] = {}

VALID_STATUSES = {
    "open", "in_progress", "acknowledged", "contained", "resolved_auto", "closed",
    "pending_approval", "closed_false_positive",
}


def create_case(alert: dict, actions: list) -> str:
    """Open a new case from an enriched alert + the actions being taken. Returns the case_id."""
    case_id = f"CASE-{next(_id_counter)}"
    case = {
        "id": case_id,
        **alert,  # title, severity, ioc, ioc_type, risk_score, etc.
        "actions": actions,
        "status": "open",
        "created_at": datetime.utcnow().isoformat(),
    }
    _CASES[case_id] = case
    return case_id


def get_case(case_id: str):
    """Return the full case dict, or None if it doesn't exist."""
    return _CASES.get(case_id)


def list_cases(limit: int = 50, severity: str | None = None) -> list:
    """Return the most recent cases, newest first. Optionally filter by severity."""
    cases = list(_CASES.values())
    if severity:
        cases = [c for c in cases if c.get("severity") == severity]
    cases.sort(key=lambda c: c["created_at"], reverse=True)
    return cases[:limit]


def update_case_status(case_id: str, status: str) -> bool:
    """Update a case's status. Returns True if the case existed and was updated, else False."""
    if status not in VALID_STATUSES:
        return False
    case = _CASES.get(case_id)
    if not case:
        return False
    case["status"] = status
    return True


# ---------------------------------------------------------------------
# Demo seed data — pre-populates the store so the dashboard has
# something to show out of the box. Safe to delete once real alerts
# are flowing in from the ingestion/enrichment pipeline.
# ---------------------------------------------------------------------

def _seed():
    seeded = [
        (
            {
                "title": "Suspicious outbound traffic to known C2 IP",
                "severity": "critical",
                "ioc": "185.220.101.7",
                "ioc_type": "ip",
                "risk_score": 92,
                "mttr_seconds": 3.8,
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
            ["quarantine_security_group", "block_ip_edge_firewall", "notify_slack"],
            "contained",
        ),
        (
            {
                "title": "Credential-stuffing pattern on VPN gateway",
                "severity": "high",
                "ioc": "45.83.64.22",
                "ioc_type": "ip",
                "risk_score": 78,
                "mttr_seconds": None,
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
            ["block_ip_edge_firewall", "notify_slack"],
            "in_progress",
        ),
        (
            {
                "title": "Malicious hash matched on endpoint (AbuseIPDB/VT)",
                "severity": "medium",
                "ioc": "d41d8cd98f00b204e9800998ecf8427e",
                "ioc_type": "hash",
                "risk_score": 55,
                "mttr_seconds": 4.6,
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
            ["isolate_host_edr", "notify_slack"],
            "resolved_auto",
        ),
        (
            {
                "title": "Data exfiltration pattern to external cloud storage",
                "severity": "critical",
                "ioc": "203.0.113.55",
                "ioc_type": "ip",
                "risk_score": 88,
                "mttr_seconds": None,
                "playbook": "isolate-ec2-and-block-ip",
                "enrichment": {
                    "abuseipdb_confidence": 74,
                    "virustotal_malicious_votes": "22/89",
                    "geo": "Singapore, SG",
                    "asn": "AS132203 (Tencent Cloud)",
                    "first_seen_in_feeds": "2026-05-14",
                },
                "timeline": [
                    {"step": "Ingested", "detail": "Received from Splunk SIEM", "offset_seconds": 0},
                    {"step": "Enriched", "detail": "AbuseIPDB + VirusTotal lookups completed", "offset_seconds": 0.5},
                    {"step": "Risk Scored", "detail": "Composite score 88/100 — critical threshold", "offset_seconds": 1.0},
                ],
            },
            ["quarantine_security_group", "block_ip_edge_firewall", "notify_slack"],
            "pending_approval",
        ),
    ]

    now = datetime.utcnow()
    offsets = [timedelta(minutes=14), timedelta(minutes=3), timedelta(hours=1), timedelta(minutes=1)]

    for (alert, actions, final_status), offset in zip(seeded, offsets):
        case_id = create_case(alert, actions)
        _CASES[case_id]["created_at"] = (now - offset).isoformat()
        update_case_status(case_id, final_status)


_seed()