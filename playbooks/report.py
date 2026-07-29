def generate_containment_report(case: dict) -> str:
    """
    Generates a structured markdown report of the incident and its containment actions.
    """
    enrichment = case.get("enrichment", {})
    timeline = case.get("timeline", [])
    
    report = f"""# SOAR Incident Containment Report: {case.get('id', 'N/A')}
**Generated At:** {case.get('created_at', 'N/A')}
**Status:** {case.get('status', 'N/A').upper()}
**Severity:** {case.get('severity', 'N/A').upper()}

## 1. Incident Overview
* **Title:** {case.get('title', 'N/A')}
* **Indicator of Compromise (IOC):** `{case.get('ioc', 'N/A')}` ({case.get('ioc_type', 'N/A').upper()})
* **Calculated Risk Score:** {case.get('risk_score', 0)}/100

## 2. Threat Intelligence Enrichment
* **GeoIP Location:** {enrichment.get('geo', 'N/A')}
* **ASN:** {enrichment.get('asn', 'N/A')}
* **AbuseIPDB Confidence Score:** {enrichment.get('abuseipdb_confidence', 'N/A')}%
* **VirusTotal Malicious Votes:** {enrichment.get('virustotal_malicious_votes', 'N/A')}
* **First Seen in Security Feeds:** {enrichment.get('first_seen_in_feeds', 'N/A')}

## 3. Automation Playbook Execution
* **Playbook Name/ID:** `{case.get('playbook', 'None')}`

### Execution Timeline:
"""
    for step in timeline:
        offset = step.get('offset_seconds', 0)
        report += f"- **T+{offset}s**: {step.get('step')} - {step.get('detail')}\n"
        
    mttr = case.get('mttr_seconds')
    if mttr:
        report += f"\n## 4. Performance Summary\n* **Mean Time to Respond (MTTR):** {mttr} seconds\n"
        
    return report
