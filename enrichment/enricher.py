"""
enrichment/enricher.py
----------------------
Central enrichment orchestrator for SOARVault.

Accepts either a raw dict alert or a NormalizedAlert Pydantic model and
enriches it with data from:
    - AbuseIPDB (IP reputation)
    - GeoIP     (geolocation + ASN)
    - VirusTotal (domain/hash/IP reputation)
    - threat_actor (repeat-attacker history)

Returns the same type that was passed in (duck-typed API):
    dict  -> enriched dict
    NormalizedAlert -> enriched NormalizedAlert with .enrichment populated

Module-level imports of each external service function are kept at the top
so that test suites can patch them via mock.patch("enrichment.enricher.X").
"""

from __future__ import annotations

import copy
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from ingestion.schema import (
    AlertStatus,
    EnrichmentData,
    IoC,
    NetworkContext,
    NormalizedAlert,
)

# Import all external service functions into this module's namespace so that
# tests can patch them with @mock.patch("enrichment.enricher.<name>").
from enrichment.abuseipdb import check_ip as query_ip
from enrichment.geoip import get_geoip as get_geolocation
from enrichment.virustotal import check_hash, check_domain, check_ioc
from enrichment.risk_scorer import calculate_risk_score
from enrichment.threat_actor import track_and_check_ip
from enrichment.cache import get_cached_ioc, set_cached_ioc
from ingestion.normalizer import IoCExtractor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich_alert(
    alert: Union[NormalizedAlert, Dict[str, Any]],
) -> Union[NormalizedAlert, Dict[str, Any]]:
    """
    Enrich a normalized alert with external threat intelligence.

    Args:
        alert: A NormalizedAlert Pydantic model OR a raw alert dict.

    Returns:
        The same type that was passed in, enriched with threat intelligence.
        Always sets status → TRIAGED (or "triaged" for dicts).
    """
    if isinstance(alert, NormalizedAlert):
        return _enrich_pydantic(alert)
    return _enrich_dict(alert)


# ---------------------------------------------------------------------------
# Internal — Pydantic path
# ---------------------------------------------------------------------------

def _enrich_pydantic(alert: NormalizedAlert) -> NormalizedAlert:
    """Enrich a NormalizedAlert model in place and return it."""
    # 1. Collect all unique IPs
    ip_list: List[str] = []
    if alert.network and alert.network.src_ip:
        ip_list.append(alert.network.src_ip)
    if alert.network and alert.network.dst_ip:
        if alert.network.dst_ip not in ip_list:
            ip_list.append(alert.network.dst_ip)

    for ioc in alert.iocs:
        if ioc.type == "ip" and ioc.value not in ip_list:
            ip_list.append(ioc.value)

    # 2. IP Abuse Scores (max score across all IPs)
    max_abuse_score: Optional[int] = None
    for ip in ip_list:
        try:
            res = query_ip(ip)
            if res and isinstance(res, dict):
                score = res.get("abuse_score")
                if score is None:
                    score = res.get("abuse_confidence_score")
                if score is not None:
                    if max_abuse_score is None or score > max_abuse_score:
                        max_abuse_score = score
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)

    # 3. GeoIP Lookup (prioritize src_ip, fall back to next IPs if error/failed)
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_asn_org: Optional[str] = None

    for ip in ip_list:
        try:
            geo = get_geolocation(ip)
            if geo and not geo.get("error") and (geo.get("country") or geo.get("country_code")):
                geo_country      = geo.get("country") or geo.get("country_name")
                geo_country_code = geo.get("country_code") or geo.get("countryCode")
                geo_asn_org      = geo.get("asn") or geo.get("as")
                if alert.network:
                    alert.network.geo_country = geo_country
                    alert.network.geo_city    = geo.get("city")
                    alert.network.asn         = geo_asn_org
                break
        except Exception as e:
            logger.warning("GeoIP lookup failed for %s: %s", ip, e)

    # 4. Repeat Attacker Check
    primary_ip = alert.network.src_ip if (alert.network and alert.network.src_ip) else (ip_list[0] if ip_list else None)
    is_repeat_attacker = False
    threat_feeds: List[str] = []

    if primary_ip:
        try:
            is_repeat_attacker = track_and_check_ip(primary_ip, alert.detected_at)
            if is_repeat_attacker:
                threat_feeds.append("REPEAT_ATTACKER")
        except Exception:
            pass

    # 5. IoC enrichment (VirusTotal: domains & hashes)
    vt_malicious: int = 0
    vt_total: int = 0

    for ioc in alert.iocs:
        try:
            if ioc.type == "domain":
                res = check_domain(ioc.value)
                if res and isinstance(res, dict):
                    m = res.get("malicious_votes", 0)
                    h = res.get("harmless_votes", 0)
                    s = res.get("suspicious_votes", 0)
                    vt_malicious += m
                    vt_total += (m + h + s)
            elif ioc.type in ("file_hash", "file_hash_md5", "file_hash_sha1", "file_hash_sha256", "hash"):
                res = check_hash(ioc.value)
                if res and isinstance(res, dict):
                    m = res.get("malicious_votes", 0)
                    h = res.get("harmless_votes", 0)
                    s = res.get("suspicious_votes", 0)
                    vt_malicious += m
                    vt_total += (m + h + s)
        except Exception as e:
            logger.warning("VT lookup failed for %s %s: %s", ioc.type, ioc.value, e)

    # 6. Composite Risk Score
    enrichment_data = {
        "abuse_score":      max_abuse_score,
        "vt_malicious":     vt_malicious,
        "vt_total":         vt_total if vt_total > 0 else None,
        "geo_country_code": geo_country_code,
        "repeat_attacker":  is_repeat_attacker,
    }
    risk_score = float(calculate_risk_score(enrichment_data))

    # 7. Populate Pydantic Model
    alert.enrichment = EnrichmentData(
        abuse_score      = max_abuse_score,
        vt_malicious     = vt_malicious,
        vt_total         = vt_total if vt_total > 0 else None,
        geo_country_code = geo_country_code,
        geo_country      = geo_country,
        geo_asn_org      = geo_asn_org,
        repeat_attacker  = is_repeat_attacker,
        threat_feeds     = threat_feeds,
        risk_score       = risk_score,
    )
    alert.status = AlertStatus.TRIAGED

    alert.add_timeline_event(
        actor  = "enrichment.enricher",
        action = "alert_enriched",
        detail = (
            f"abuse={max_abuse_score}, vt={vt_malicious}/{vt_total}, "
            f"country={geo_country_code}, risk={risk_score}, "
            f"repeat_attacker={is_repeat_attacker}"
        ),
    )
    return alert


# ---------------------------------------------------------------------------
# Internal — dict path
# ---------------------------------------------------------------------------

def _enrich_dict(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich a raw alert dict and return it enriched."""
    alert = copy.deepcopy(alert)

    extractor = IoCExtractor()
    extracted_iocs = []

    # If description or text is present, extract additional IoCs if needed
    text_blob = f"{alert.get('title', '')} {alert.get('description', '')}"
    if text_blob.strip():
        extracted_iocs = extractor.extract_from_text(text_blob)

    # Combine pre-existing iocs dicts and extracted IoC objects
    all_iocs = alert.get("iocs", []) or []

    # 1. Collect all unique IPs
    ip_list: List[str] = []
    network = alert.get("network", {}) or {}
    src_ip  = network.get("src_ip")
    dst_ip  = network.get("dst_ip")

    if src_ip and src_ip not in ip_list:
        ip_list.append(src_ip)
    if dst_ip and dst_ip not in ip_list:
        ip_list.append(dst_ip)

    for ioc in all_iocs:
        if isinstance(ioc, dict) and ioc.get("type") == "ip" and ioc.get("value") not in ip_list:
            ip_list.append(ioc.get("value"))

    for ioc in extracted_iocs:
        if ioc.type == "ip" and ioc.value not in ip_list:
            ip_list.append(ioc.value)

    # 2. IP Abuse Scores (max score across all IPs)
    max_abuse_score: Optional[int] = None
    for ip in ip_list:
        try:
            res = query_ip(ip)
            if res and isinstance(res, dict):
                score = res.get("abuse_score")
                if score is None:
                    score = res.get("abuse_confidence_score")
                if score is not None:
                    if max_abuse_score is None or score > max_abuse_score:
                        max_abuse_score = score
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)

    # 3. GeoIP Lookup (prioritize src_ip, fallback to next IPs)
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_asn_org: Optional[str] = None

    for ip in ip_list:
        try:
            geo = get_geolocation(ip)
            if geo and not geo.get("error") and (geo.get("country") or geo.get("country_code")):
                geo_country      = geo.get("country") or geo.get("country_name")
                geo_country_code = geo.get("country_code") or geo.get("countryCode")
                geo_asn_org      = geo.get("asn") or geo.get("as")
                if "network" not in alert or alert["network"] is None:
                    alert["network"] = {}
                alert["network"]["geo_country"] = geo_country
                alert["network"]["geo_city"]    = geo.get("city")
                alert["network"]["asn"]         = geo_asn_org
                break
        except Exception as e:
            logger.warning("GeoIP lookup failed for %s: %s", ip, e)

    # 4. Repeat Attacker Check
    primary_ip = src_ip or (ip_list[0] if ip_list else None)
    is_repeat_attacker = False
    threat_feeds: List[str] = []

    if primary_ip:
        detected_at = alert.get("detected_at")
        try:
            is_repeat_attacker = track_and_check_ip(primary_ip, detected_at)
            if is_repeat_attacker:
                threat_feeds.append("REPEAT_ATTACKER")
        except Exception:
            pass

    # 5. IoC enrichment (VirusTotal)
    vt_malicious: int = 0
    vt_total: int = 0

    # Domains & Hashes from dict list
    domains_to_check: set = set()
    hashes_to_check: set = set()

    for ioc in all_iocs:
        if isinstance(ioc, dict):
            t = ioc.get("type", "")
            v = ioc.get("value", "")
            if t == "domain" and v:
                domains_to_check.add(v)
            elif t in ("file_hash", "file_hash_md5", "file_hash_sha1", "file_hash_sha256", "hash") and v:
                hashes_to_check.add(v)

    for ioc in extracted_iocs:
        if ioc.type == "domain" and ioc.value:
            domains_to_check.add(ioc.value)
        elif ioc.type in ("file_hash", "file_hash_md5", "file_hash_sha1", "file_hash_sha256", "hash") and ioc.value:
            hashes_to_check.add(ioc.value)

    for domain in domains_to_check:
        try:
            res = check_domain(domain)
            if res and isinstance(res, dict):
                m = res.get("malicious_votes", 0)
                h = res.get("harmless_votes", 0)
                s = res.get("suspicious_votes", 0)
                vt_malicious += m
                vt_total += (m + h + s)
        except Exception as e:
            logger.warning("VT domain lookup failed for %s: %s", domain, e)

    for file_hash in hashes_to_check:
        try:
            res = check_hash(file_hash)
            if res and isinstance(res, dict):
                m = res.get("malicious_votes", 0)
                h = res.get("harmless_votes", 0)
                s = res.get("suspicious_votes", 0)
                vt_malicious += m
                vt_total += (m + h + s)
        except Exception as e:
            logger.warning("VT hash lookup failed for %s: %s", file_hash, e)

    # 6. Composite Risk Score
    enrichment_data_dict = {
        "abuse_score":      max_abuse_score if max_abuse_score is not None else 0,
        "vt_malicious":     vt_malicious,
        "vt_total":         vt_total if vt_total > 0 else 70,
        "geo_country_code": geo_country_code,
        "repeat_attacker":  is_repeat_attacker,
    }
    risk_score = float(calculate_risk_score(enrichment_data_dict))

    # 7. Write enrichment subdict
    alert["enrichment"] = {
        "abuse_score":      max_abuse_score,
        "vt_malicious":     vt_malicious,
        "vt_total":         vt_total if vt_total > 0 else None,
        "geo_country_code": geo_country_code,
        "geo_country":      geo_country,
        "geo_asn_org":      geo_asn_org,
        "repeat_attacker":  is_repeat_attacker,
        "threat_feeds":     threat_feeds,
        "risk_score":       risk_score,
    }
    alert["status"] = "triaged"

    # 8. Timeline
    if "timeline" not in alert:
        alert["timeline"] = []
    alert["timeline"].append({
        "ts":     datetime.now(timezone.utc).isoformat(),
        "actor":  "enrichment.enricher",
        "action": "alert_enriched",
        "detail": (
            f"abuse={max_abuse_score}, vt={vt_malicious}/{vt_total}, "
            f"country={geo_country_code}, risk={risk_score}, "
            f"repeat_attacker={is_repeat_attacker}"
        ),
    })

    return alert
