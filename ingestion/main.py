import json
from ingestion.schema import RawAlert, Case
from ingestion.normalizer import normalize_alert
from enrichment.enricher import enrich_alert
from playbooks.engine import PlaybookEngine
from ingestion.database import get_redis_client

def ingest_raw_alert(raw_alert: RawAlert) -> dict:
    """
    Standardizes a raw alert, runs threat intelligence enrichment, 
    evaluates matching playbooks, opens cases, and triggers containment.
    """
    db = get_redis_client()
    
    # 1. Normalize
    normalized = normalize_alert(raw_alert)
    print(f"[*] Ingested raw alert from {raw_alert.source}. Standardized to {normalized.id}")
    
    # Store initial state in Redis with "in_progress" to simulate work in flight
    normalized.enrichment_status = "in_progress"
    db.set(f"alert:{normalized.id}", normalized.model_dump_json())
    db.lpush("alerts_list", normalized.id)
    
    # 2. Enrich IOCs
    enrichment_result = enrich_alert(normalized)
    normalized.enrichment_status = "complete"
    db.set(f"alert:{normalized.id}", normalized.model_dump_json())
    
    # Increment global ingested alerts metric
    db.incr("metrics:alerts_ingested_24h")
    
    # 3. Playbook Evaluation
    engine = PlaybookEngine()
    context = {
        "risk_score": enrichment_result.get("risk_score", 0),
        "ioc_type": normalized.ioc_type,
        "severity": normalized.severity,
        "source": normalized.source,
        "rule_name": normalized.title,
        "title": normalized.title
    }
    
    matched_pb = engine.select_playbook(context)
    
    if matched_pb:
        # Create a sequential Case ID
        try:
            case_seq = db.incr("counters:case_id")
            if case_seq < 1000:
                db.set("counters:case_id", 1004)
                case_seq = 1004
        except Exception:
            import random
            case_seq = random.randint(1005, 1200)
            
        case_id = f"CASE-{case_seq}"
        
        # Decide if manual authorization is needed (critical alerts or risk >= 80)
        risk_score = enrichment_result.get("risk_score", 0)
        is_high_impact = normalized.severity == "critical" or risk_score >= 80
        status = "pending_approval" if is_high_impact else "open"
        
        # Build initial timeline
        timeline = [
            {"step": "Ingested", "detail": f"Received from {normalized.source}", "offset_seconds": 0.0},
            {"step": "Enriched", "detail": "AbuseIPDB + VirusTotal lookups completed", "offset_seconds": 0.5},
            {"step": "Risk Scored", "detail": f"Composite score {risk_score}/100 — threat analysis complete", "offset_seconds": 1.0}
        ]
        
        if is_high_impact:
            timeline.append({
                "step": "Playbook Triggered",
                "detail": f"Matched playbook '{matched_pb['name']}'. High risk: awaiting authorization.",
                "offset_seconds": 1.2
            })
        else:
            timeline.append({
                "step": "Playbook Triggered",
                "detail": f"Matched playbook '{matched_pb['name']}' automatically.",
                "offset_seconds": 1.2
            })
            
        case = Case(
            id=case_id,
            title=normalized.title,
            severity=normalized.severity,
            ioc=normalized.ioc_value,
            ioc_type=normalized.ioc_type,
            risk_score=risk_score,
            mttr_seconds=None,
            playbook=matched_pb["id"],
            status=status,
            created_at=normalized.received_at,
            enrichment=enrichment_result["enrichment"],
            timeline=timeline,
            actions=matched_pb["actions"]
        )
        
        # Save case details in Redis
        db.set(f"case:{case_id}", case.model_dump_json())
        db.lpush("cases_list", case_id)
        print(f"[*] Opened case {case_id} for alert {normalized.id} (status={status})")
        
        # Execute playbook containment actions (if open)
        engine.execute(case_id, approved=False)
        
        return {"alert_id": normalized.id, "case_id": case_id, "playbook_matched": matched_pb["id"]}
    else:
        print(f"[*] Alert {normalized.id} did not match any active playbook triggers.")
        return {"alert_id": normalized.id, "case_id": None, "playbook_matched": None}
