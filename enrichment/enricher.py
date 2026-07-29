from datetime import datetime
from ingestion.schema import NormalizedAlert
from enrichment.cache import get_cached_ioc, set_cached_ioc
from enrichment.abuseipdb import check_ip
from enrichment.virustotal import check_ioc
from enrichment.geoip import get_geoip
from enrichment.risk_scorer import calculate_risk_score

def enrich_alert(alert: NormalizedAlert) -> dict:
    """
    Orchestrates the entire enrichment process for a standardized alert.
    Retrieves data from Cache/GeoIP/AbuseIPDB/VirusTotal, scores the risk, 
    and caches the results.
    """
    ioc = alert.ioc_value
    ioc_type = alert.ioc_type
    
    # Try loading from cache
    cached = get_cached_ioc(ioc)
    if cached:
        print(f"[*] Enrichment cache hit for IOC: {ioc}")
        return cached

    print(f"[*] Enrichment cache miss. Enriching IOC: {ioc} ({ioc_type})")
    
    abuseipdb_confidence = None
    virustotal_malicious_votes = None
    geo = None
    asn = None
    first_seen_in_feeds = datetime.utcnow().strftime("%Y-%m-%d")
    
    if ioc_type == "ip":
        # 1. GeoIP Lookups
        geo_data = get_geoip(ioc)
        if geo_data:
            country_code = geo_data.get("country_code", "")
            city = geo_data.get("city", "")
            geo = f"{city}, {country_code}" if city and country_code else country_code or None
            asn = geo_data.get("asn")
            
        # 2. AbuseIPDB
        abuse_data = check_ip(ioc)
        abuseipdb_confidence = abuse_data.get("abuse_confidence_score")
        
        # 3. VirusTotal IP Reputation
        vt_data = check_ioc(ioc, "ip")
        malicious = vt_data.get("malicious_votes", 0)
        total = vt_data.get("total_votes", 72)
        virustotal_malicious_votes = f"{malicious}/{total}"
        
    elif ioc_type == "hash":
        # 1. VirusTotal File Hash Reputation
        vt_data = check_ioc(ioc, "hash")
        malicious = vt_data.get("malicious_votes", 0)
        total = vt_data.get("total_votes", 72)
        virustotal_malicious_votes = f"{malicious}/{total}"
        
    # Calculate Composite Risk Score
    risk_score = calculate_risk_score(alert.severity, abuseipdb_confidence, virustotal_malicious_votes)
    
    result = {
        "risk_score": risk_score,
        "enrichment": {
            "abuseipdb_confidence": abuseipdb_confidence,
            "virustotal_malicious_votes": virustotal_malicious_votes,
            "geo": geo,
            "asn": asn,
            "first_seen_in_feeds": first_seen_in_feeds
        }
    }
    
    # Save to Cache
    set_cached_ioc(ioc, result)
    return result
