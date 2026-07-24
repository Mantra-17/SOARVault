"""
Unified alert enrichment module.
Co-ordinates scanning lookups from AbuseIPDB, GeoIP, and VirusTotal,
calculates a composite risk score, and attaches threat intel metadata to the alert.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from enrichment.abuseipdb import query_ip
from enrichment.geoip import get_geolocation
from enrichment.virustotal import check_hash, check_domain
from enrichment.risk_scorer import calculate_risk_score
from enrichment.threat_actor import track_and_check_ip
from enrichment.ioc_extractor import extract_iocs
from ingestion.schema import NormalizedAlert, EnrichmentData, AlertStatus

logger = logging.getLogger(__name__)


def enrich_alert(alert: Any) -> Any:
    """
    Enrich a normalized alert with threat intelligence.
    Supports both Pydantic NormalizedAlert models and standard dictionaries.
    
    Returns:
        The enriched alert of the same type as the input (Pydantic model or dict).
    """
    is_pydantic = isinstance(alert, NormalizedAlert)

    # 1. Helper helper to safely fetch fields from dicts or objects
    def _get_val(obj: Any, key: str, default: Any = None) -> Any:
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    if is_pydantic:
        alert_dict = alert.model_dump()
    else:
        alert_dict = alert

    # 2. Extract all IoCs from the alert payload
    extracted = extract_iocs(alert_dict)

    # 3. Merge extracted IoCs into existing ones
    existing_iocs = _get_val(alert, "iocs") or []
    seen_iocs = set()
    merged_iocs = []

    # Process existing IoCs first
    for ioc in existing_iocs:
        ioc_type = _get_val(ioc, "type")
        ioc_val = _get_val(ioc, "value")
        if ioc_type and ioc_val:
            key = (ioc_type, ioc_val.lower().strip())
            if key not in seen_iocs:
                seen_iocs.add(key)
                merged_iocs.append(ioc)

    # Add newly extracted IoCs if not already present
    for ioc in extracted:
        key = (ioc.type, ioc.value.lower().strip())
        if key not in seen_iocs:
            seen_iocs.add(key)
            if is_pydantic:
                merged_iocs.append(ioc)
            else:
                merged_iocs.append({
                    "type": ioc.type,
                    "value": ioc.value,
                    "context": ioc.context
                })

    # 4. Identify the primary IP to prioritize for geolocation enrichment
    primary_ip = None
    network_val = _get_val(alert_dict, "network")
    if network_val:
        primary_ip = _get_val(network_val, "src_ip")
    if not primary_ip:
        for ioc in merged_iocs:
            ioc_type = _get_val(ioc, "type")
            if ioc_type == "ip":
                primary_ip = _get_val(ioc, "value")
                break

    # 4b. Track the primary IP and check if it is a repeat attacker
    repeat_attacker = False
    if primary_ip:
        detected_at = _get_val(alert, "detected_at")
        repeat_attacker = track_and_check_ip(primary_ip, detected_at)

    # 5. Call AbuseIPDB and GeoIP for all unique IPs
    abuse_scores = []
    geo_results = {}

    for ioc in merged_iocs:
        ioc_type = _get_val(ioc, "type")
        ioc_val = _get_val(ioc, "value")
        if ioc_type == "ip":
            try:
                abuse_res = query_ip(ioc_val)
                score = abuse_res.get("abuse_score")
                if score is not None:
                    abuse_scores.append(score)
            except Exception as e:
                logger.error(f"AbuseIPDB query failed for IP {ioc_val}: {e}")

            try:
                geo_data = get_geolocation(ioc_val)
                if geo_data and not geo_data.get("error"):
                    geo_results[ioc_val] = geo_data
            except Exception as e:
                logger.error(f"GeoIP query failed for IP {ioc_val}: {e}")

    # Final IP scoring & geo-data selection
    abuse_score = max(abuse_scores) if abuse_scores else None

    final_geo_data = None
    if primary_ip and primary_ip in geo_results:
        final_geo_data = geo_results[primary_ip]
    elif geo_results:
        final_geo_data = next(iter(geo_results.values()))

    geo_country_code = None
    geo_asn_org = None
    if final_geo_data:
        geo_country_code = final_geo_data.get("country_code")
        geo_asn_org = final_geo_data.get("asn")

    # 6. Call VirusTotal check_domain and check_hash for relevant IoCs
    vt_malicious = None
    vt_total = None
    for ioc in merged_iocs:
        ioc_type = _get_val(ioc, "type")
        ioc_val = _get_val(ioc, "value")

        if ioc_type == "domain":
            try:
                vt_res = check_domain(ioc_val)
                if vt_malicious is None:
                    vt_malicious = 0
                    vt_total = 0
                vt_malicious += vt_res.get("malicious_votes", 0)
                vt_total += (
                    vt_res.get("malicious_votes", 0) +
                    vt_res.get("harmless_votes", 0) +
                    vt_res.get("suspicious_votes", 0)
                )
            except Exception as e:
                logger.error(f"VirusTotal domain check failed for {ioc_val}: {e}")
        elif ioc_type in ("file_hash", "file_hash_md5", "file_hash_sha1", "file_hash_sha256"):
            try:
                vt_res = check_hash(ioc_val)
                if vt_malicious is None:
                    vt_malicious = 0
                    vt_total = 0
                vt_malicious += vt_res.get("malicious_votes", 0)
                vt_total += (
                    vt_res.get("malicious_votes", 0) +
                    vt_res.get("harmless_votes", 0) +
                    vt_res.get("suspicious_votes", 0)
                )
            except Exception as e:
                logger.error(f"VirusTotal hash check failed for {ioc_val}: {e}")

    # 7. Calculate composite risk score using risk scorer
    scorer_data = {
        "abuse_score": abuse_score or 0,
        "vt_malicious": vt_malicious or 0,
        "vt_total": vt_total or 0,
        "geo_country_code": geo_country_code,
        "repeat_attacker": repeat_attacker,
    }
    risk_score = calculate_risk_score(scorer_data)

    # 8. Build the final enrichment data block
    enrichment_dict = {
        "abuse_score": abuse_score,
        "vt_malicious": vt_malicious,
        "vt_total": vt_total,
        "is_tor_exit": None,
        "is_vpn": None,
        "threat_feeds": ["REPEAT_ATTACKER"] if repeat_attacker else [],
        "geo_country_code": geo_country_code,
        "geo_asn_org": geo_asn_org,
        "repeat_attacker": repeat_attacker,
        "risk_score": float(risk_score),
    }

    # 9. Update and return alert depending on type (Pydantic object vs dict)
    if is_pydantic:
        alert.iocs = merged_iocs
        alert.enrichment = EnrichmentData(**enrichment_dict)
        alert.status = AlertStatus.TRIAGED

        # Enrich network fields if they aren't already set
        if alert.network and final_geo_data:
            if not alert.network.geo_country:
                alert.network.geo_country = final_geo_data.get("country")
            if not alert.network.geo_city:
                alert.network.geo_city = final_geo_data.get("city")
            if not alert.network.asn:
                alert.network.asn = final_geo_data.get("asn")

        alert.add_timeline_event(
            actor="enrichment.enricher",
            action="alert_enriched",
            detail=f"risk_score={risk_score}, geo_country_code={geo_country_code}"
        )
        return alert
    else:
        enriched_alert = alert.copy()
        enriched_alert["iocs"] = merged_iocs
        enriched_alert["enrichment"] = enrichment_dict
        enriched_alert["status"] = "triaged"

        # Enrich network dictionary fields if available
        if "network" in enriched_alert and isinstance(enriched_alert["network"], dict):
            net_dict = enriched_alert["network"].copy()
            if final_geo_data:
                if not net_dict.get("geo_country"):
                    net_dict["geo_country"] = final_geo_data.get("country")
                if not net_dict.get("geo_city"):
                    net_dict["geo_city"] = final_geo_data.get("city")
                if not net_dict.get("asn"):
                    net_dict["asn"] = final_geo_data.get("asn")
            enriched_alert["network"] = net_dict

        # Log timeline event in the list
        timeline = enriched_alert.get("timeline")
        if isinstance(timeline, list):
            timeline = list(timeline)
        else:
            timeline = []
        timeline.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": "enrichment.enricher",
            "action": "alert_enriched",
            "detail": f"risk_score={risk_score}, geo_country_code={geo_country_code}"
        })
        enriched_alert["timeline"] = timeline
        return enriched_alert
