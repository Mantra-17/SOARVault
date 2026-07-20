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

    # 2. Extract primary attacking IP
    ip = None
    network = _get_val(alert, "network")
    if network:
        ip = _get_val(network, "src_ip")

    iocs = _get_val(alert, "iocs") or []
    if not ip:
        for ioc in iocs:
            ioc_type = _get_val(ioc, "type")
            ioc_val = _get_val(ioc, "value")
            if ioc_type == "ip":
                ip = ioc_val
                break

    # 3. Call AbuseIPDB and GeoIP in sequence if IP is present
    abuse_score = None
    if ip:
        try:
            abuse_res = query_ip(ip)
            abuse_score = abuse_res.get("abuse_score")
        except Exception as e:
            logger.error(f"AbuseIPDB query failed for IP {ip}: {e}")

    geo_country_code = None
    geo_asn_org = None
    geo_data = None
    if ip:
        try:
            geo_data = get_geolocation(ip)
            if geo_data and not geo_data.get("error"):
                geo_country_code = geo_data.get("country_code")
                geo_asn_org = geo_data.get("asn")
        except Exception as e:
            logger.error(f"GeoIP query failed for IP {ip}: {e}")

    # 4. Call VirusTotal check_domain and check_hash for relevant IoCs
    vt_malicious = None
    vt_total = None
    for ioc in iocs:
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

    # 5. Calculate composite risk score using risk scorer
    scorer_data = {
        "abuse_score": abuse_score or 0,
        "vt_malicious": vt_malicious or 0,
        "vt_total": vt_total or 0,
        "geo_country_code": geo_country_code,
    }
    risk_score = calculate_risk_score(scorer_data)

    # 6. Build the final enrichment data block
    enrichment_dict = {
        "abuse_score": abuse_score,
        "vt_malicious": vt_malicious,
        "vt_total": vt_total,
        "is_tor_exit": None,
        "is_vpn": None,
        "threat_feeds": [],
        "geo_country_code": geo_country_code,
        "geo_asn_org": geo_asn_org,
        "risk_score": float(risk_score),
    }

    # 7. Update and return alert depending on type (Pydantic object vs dict)
    if is_pydantic:
        alert.enrichment = EnrichmentData(**enrichment_dict)
        alert.status = AlertStatus.TRIAGED

        # Enrich network fields if they aren't already set
        if alert.network and geo_data and not geo_data.get("error"):
            if not alert.network.geo_country:
                alert.network.geo_country = geo_data.get("country")
            if not alert.network.geo_city:
                alert.network.geo_city = geo_data.get("city")
            if not alert.network.asn:
                alert.network.asn = geo_data.get("asn")

        alert.add_timeline_event(
            actor="enrichment.enricher",
            action="alert_enriched",
            detail=f"risk_score={risk_score}, geo_country_code={geo_country_code}"
        )
        return alert
    else:
        enriched_alert = alert.copy()
        enriched_alert["enrichment"] = enrichment_dict
        enriched_alert["status"] = "triaged"

        # Enrich network dictionary fields if available
        if "network" in enriched_alert and isinstance(enriched_alert["network"], dict):
            net_dict = enriched_alert["network"].copy()
            if geo_data and not geo_data.get("error"):
                if not net_dict.get("geo_country"):
                    net_dict["geo_country"] = geo_data.get("country")
                if not net_dict.get("geo_city"):
                    net_dict["geo_city"] = geo_data.get("city")
                if not net_dict.get("asn"):
                    net_dict["asn"] = geo_data.get("asn")
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
