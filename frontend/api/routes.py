"""
api/routes.py — Mock REST API for the frontend to consume.

Endpoints:
  GET  /api/metrics         -> MTTR + volume KPIs for the header strip
  GET  /api/alerts          -> incoming raw SIEM alerts (pre-enrichment)
  GET  /api/cases           -> enriched, actioned incident cases (alias of /incidents)
  GET  /api/cases/<id>      -> single case detail (alias of /incidents/<id>)
  GET  /api/playbooks       -> available containment playbooks
  POST /api/cases/<id>/ack  -> acknowledge a case (SOC Analyst action)
  POST /api/auth/login      -> validate credentials, return role (alias of /login)
  GET  /api/integrations    -> connected SIEM/enrichment/orchestration systems
  PUT  /api/playbooks/<id>  -> edit a playbook (admin only)

  GET  /api/incidents       -> list all incidents, filters: ?severity=, ?status=, ?limit=
  GET  /api/incidents/<id>  -> single incident details
  GET  /api/stats           -> total, critical, resolved, pending counts
  POST /api/login           -> validate credentials, return role

Replace the in-memory data with calls into the real ingestion /
enrichment / orchestration modules once teammates land that code.
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from frontend.case_manager import list_cases, get_case
from frontend.rbac import get_role, has_permission, authenticate

api = Blueprint("api", __name__)

MOCK_INTEGRATIONS = [
    {"id": "splunk", "name": "Splunk SIEM", "type": "alert_source", "status": "connected", "last_event": "8s ago"},
    {"id": "qradar", "name": "QRadar SIEM", "type": "alert_source", "status": "connected", "last_event": "41s ago"},
    {"id": "crowdstrike", "name": "CrowdStrike EDR", "type": "alert_source", "status": "connected", "last_event": "3m ago"},
    {"id": "abuseipdb", "name": "AbuseIPDB", "type": "enrichment", "status": "connected", "last_event": "6s ago"},
    {"id": "virustotal", "name": "VirusTotal", "type": "enrichment", "status": "connected", "last_event": "6s ago"},
    {"id": "aws-sdk", "name": "AWS SDK (EC2 isolation)", "type": "orchestration", "status": "connected", "last_event": "14m ago"},
    {"id": "palo-alto", "name": "Palo Alto Firewall API", "type": "orchestration", "status": "degraded", "last_event": "2h ago"},
    {"id": "slack", "name": "Slack notifications", "type": "notification", "status": "connected", "last_event": "3m ago"},
]

MOCK_ALERTS = [
    {
        "id": "ALRT-88231",
        "source": "Splunk SIEM",
        "ioc_type": "ip",
        "ioc_value": "185.220.101.7",
        "rule": "Outbound connection to Tor exit node",
        "severity": "critical",
        "received_at": (datetime.utcnow() - timedelta(minutes=14, seconds=8)).isoformat(),
        "enrichment_status": "complete",
    },
    {
        "id": "ALRT-88240",
        "source": "QRadar SIEM",
        "ioc_type": "ip",
        "ioc_value": "45.83.64.22",
        "rule": "Repeated auth failures across 40 accounts",
        "severity": "high",
        "received_at": (datetime.utcnow() - timedelta(minutes=3, seconds=2)).isoformat(),
        "enrichment_status": "in_progress",
    },
    {
        "id": "ALRT-88255",
        "source": "CrowdStrike EDR",
        "ioc_type": "hash",
        "ioc_value": "d41d8cd98f00b204e9800998ecf8427e",
        "rule": "Known-malicious binary hash executed",
        "severity": "medium",
        "received_at": (datetime.utcnow() - timedelta(hours=1, minutes=1)).isoformat(),
        "enrichment_status": "complete",
    },
    {
        "id": "ALRT-88261",
        "source": "Palo Alto Firewall",
        "ioc_type": "ip",
        "ioc_value": "192.0.2.44",
        "rule": "Port scan detected from internal host",
        "severity": "low",
        "received_at": (datetime.utcnow() - timedelta(minutes=1)).isoformat(),
        "enrichment_status": "queued",
    },
]

MOCK_PLAYBOOKS = [
    {
        "id": "isolate-ec2-and-block-ip",
        "name": "Isolate EC2 + Block IP",
        "trigger": "risk_score >= 85 and ioc_type == 'ip'",
        "actions": ["quarantine_security_group", "block_ip_edge_firewall", "notify_slack"],
        "avg_exec_seconds": 3.9,
    },
    {
        "id": "block-ip-firewall",
        "name": "Block IP at Perimeter Firewall",
        "trigger": "risk_score >= 60 and ioc_type == 'ip'",
        "actions": ["block_ip_edge_firewall", "notify_slack"],
        "avg_exec_seconds": 2.1,
    },
    {
        "id": "quarantine-endpoint",
        "name": "Quarantine Endpoint (EDR)",
        "trigger": "risk_score >= 50 and ioc_type == 'hash'",
        "actions": ["isolate_host_edr", "notify_slack"],
        "avg_exec_seconds": 4.6,
    },
]


@api.get("/metrics")
def metrics():
    cases = list_cases()
    resolved = [c for c in cases if c["mttr_seconds"]]
    avg_mttr = round(sum(c["mttr_seconds"] for c in resolved) / len(resolved), 2) if resolved else 0
    return jsonify({
        "mttr_avg_seconds": avg_mttr,
        "mttr_target_seconds": 5.0,
        "alerts_ingested_24h": 412,
        "cases_auto_contained_24h": 37,
        "analyst_hours_saved_24h": 18.5,
    })


@api.get("/alerts")
def alerts():
    return jsonify(MOCK_ALERTS)


@api.get("/cases")
def cases():
    return jsonify(list_cases())


@api.get("/cases/<case_id>")
def case_detail(case_id):
    case = get_case(case_id)
    if not case:
        return jsonify({"error": "case not found"}), 404
    return jsonify(case)


# ---------------------------------------------------------------------
# Checklist-spec endpoints (/incidents, /stats, /login).
# These are the canonical names used going forward; /cases, /metrics
# and /auth/login above are kept as aliases so nothing already wired
# up in the frontend breaks.
# ---------------------------------------------------------------------

@api.get("/incidents")
def list_incidents():
    """GET /api/incidents — list all incidents, with optional filters.

    Query params:
      severity  e.g. ?severity=critical
      status    e.g. ?status=in_progress
      limit     e.g. ?limit=10  (default 50)
    """
    severity = request.args.get("severity")
    status = request.args.get("status")
    limit = request.args.get("limit", default=50, type=int)

    incidents = list_cases(limit=limit, severity=severity)
    if status:
        incidents = [i for i in incidents if i.get("status") == status]
    return jsonify(incidents)


@api.get("/incidents/<incident_id>")
def incident_detail(incident_id):
    """GET /api/incidents/:id — single incident details."""
    incident = get_case(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    return jsonify(incident)


@api.get("/stats")
def stats():
    """GET /api/stats — total, critical, resolved, pending counts."""
    all_cases = list_cases(limit=10_000)
    total = len(all_cases)
    critical = sum(1 for c in all_cases if c.get("severity") == "critical")
    resolved = sum(1 for c in all_cases if c.get("status") in ("resolved_auto", "contained"))
    pending = sum(1 for c in all_cases if c.get("status") in ("open", "in_progress"))
    return jsonify({
        "total": total,
        "critical": critical,
        "resolved": resolved,
        "pending": pending,
    })


@api.post("/login")
def login_v2():
    """POST /api/login — validate credentials, return role."""
    return login()

@api.get("/playbooks")
def playbooks():
    return jsonify(MOCK_PLAYBOOKS)


@api.post("/cases/<case_id>/ack")
def ack_case(case_id):
    case = get_case(case_id)
    if not case:
        return jsonify({"error": "case not found"}), 404
    case["status"] = "acknowledged"
    return jsonify(case)


@api.post("/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    session = authenticate(username, password)
    if not session:
        return jsonify({"error": "invalid credentials"}), 401
    role = get_role(session["role"])
    return jsonify({
        "username": session["username"],
        "role": session["role"],
        "role_label": session["role_label"],
        "permissions": role["permissions"],
    })


@api.get("/integrations")
def integrations():
    return jsonify(MOCK_INTEGRATIONS)


@api.put("/playbooks/<playbook_id>")
def update_playbook(playbook_id):
    role = request.headers.get("X-Role", "analyst")
    if not has_permission(role, "edit"):
        return jsonify({"error": "forbidden — admin role required to edit playbooks"}), 403

    body = request.get_json(silent=True) or {}
    playbook = next((p for p in MOCK_PLAYBOOKS if p["id"] == playbook_id), None)
    if not playbook:
        return jsonify({"error": "playbook not found"}), 404

    playbook["trigger"] = body.get("trigger", playbook["trigger"])
    playbook["actions"] = body.get("actions", playbook["actions"])
    return jsonify(playbook)