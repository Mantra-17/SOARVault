import json
from datetime import datetime, timedelta
from ingestion.database import get_redis_client

VALID_STATUSES = {
    "open", "in_progress", "acknowledged", "contained", "resolved_auto", "closed",
    "pending_approval", "closed_false_positive",
}

def create_case(alert: dict, actions: list) -> str:
    """Open a new case from an enriched alert + actions. Returns case_id."""
    db = get_redis_client()
    try:
        case_seq = db.incr("counters:case_id")
        if case_seq < 1000:
            db.set("counters:case_id", 1004)
            case_seq = 1004
    except Exception:
        import random
        case_seq = random.randint(1005, 2000)

    case_id = f"CASE-{case_seq}"
    case = {
        "id": case_id,
        **alert,  # title, severity, ioc, ioc_type, risk_score, etc.
        "actions": actions,
        "status": "open",
        "created_at": datetime.utcnow().isoformat(),
    }
    db.set(f"case:{case_id}", json.dumps(case))
    db.lpush("cases_list", case_id)
    return case_id

def get_case(case_id: str) -> dict or None:
    """Return the full case dict from Redis, or None if not found."""
    db = get_redis_client()
    data = db.get(f"case:{case_id}")
    if data:
        return json.loads(data)
    return None

def list_cases(limit: int = 50, severity: str or None = None) -> list:
    """Return the most recent cases, newest first. Optionally filter by severity."""
    db = get_redis_client()
    case_ids = db.lrange("cases_list", 0, -1)
    cases = []
    
    for cid in case_ids:
        c_data = db.get(f"case:{cid}")
        if c_data:
            c = json.loads(c_data)
            if severity and c.get("severity") != severity:
                continue
            cases.append(c)
            
    # Sort by created_at descending (newest first)
    cases.sort(key=lambda c: c.get("created_at", ""), reverse=True)
    return cases[:limit]

def update_case_status(case_id: str, status: str) -> bool:
    """Update a case's status. Returns True if successful."""
    if status not in VALID_STATUSES:
        return False
    db = get_redis_client()
    c_data = db.get(f"case:{case_id}")
    if not c_data:
        return False
    case = json.loads(c_data)
    case["status"] = status
    db.set(f"case:{case_id}", json.dumps(case))
    return True

def seed_database():
    """Seeds default cases and metrics if the store is empty."""
    db = get_redis_client()
    
    # Check if we already have cases to avoid double seeding
    if db.exists("cases_list") and db.llen("cases_list") > 0:
        print("[*] Database already contains cases. Skipping seeding.")
        return

    print("[*] Database is empty. Seeding initial cases and metrics...")
    
    # Seed metrics
    db.set("metrics:mttr_avg_seconds", "4.2")
    db.set("metrics:alerts_ingested_24h", "412")
    db.set("metrics:cases_auto_contained_24h", "37")
    db.set("metrics:analyst_hours_saved_24h", "18.5")
    db.set("counters:case_id", 1004)

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
            timedelta(minutes=14)
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
            timedelta(minutes=3)
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
            timedelta(hours=1)
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
            timedelta(minutes=1)
        ),
    ]

    now = datetime.utcnow()
    case_ids = []
    
    # We assign static IDs starting from 1001 for matching demo visuals
    for idx, (alert, actions, final_status, offset) in enumerate(seeded):
        cid = f"CASE-{1001 + idx}"
        case = {
            "id": cid,
            **alert,
            "actions": actions,
            "status": final_status,
            "created_at": (now - offset).isoformat(),
        }
        db.set(f"case:{cid}", json.dumps(case))
        db.lpush("cases_list", cid)
        
    print("[*] Seeding completed.")

# Automatically run seeding logic on import
try:
    seed_database()
except Exception as e:
    print(f"[!] Error seeding database: {e}")