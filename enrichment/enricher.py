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

import logging
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
    src_ip = alert.ioc_value if alert.ioc_type == "ip" else (
        alert.network.src_ip if alert.network else None
    )

    abuse_score: Optional[int] = None
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_asn_org: Optional[str] = None
    vt_malicious: int = 0
    vt_total: int = 0
    is_repeat_attacker: bool = False

    # ---- IP enrichment -------------------------------------------------- #
    if src_ip:
        # AbuseIPDB
        try:
            abuse_data = query_ip(src_ip)
            abuse_score = abuse_data.get("abuse_score") or abuse_data.get("abuse_confidence_score")
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", src_ip, e)

        # GeoIP
        try:
            geo = get_geolocation(src_ip)
            if geo:
                geo_country      = geo.get("country") or geo.get("country_name")
                geo_country_code = geo.get("country_code") or geo.get("countryCode")
                geo_asn_org      = geo.get("asn") or geo.get("as")
                # Populate network context fields
                if alert.network:
                    alert.network.geo_country = geo_country
                    alert.network.geo_city    = geo.get("city")
                    alert.network.asn         = geo_asn_org
        except Exception as e:
            logger.warning("GeoIP lookup failed for %s: %s", src_ip, e)

        # Threat actor history
        try:
            is_repeat_attacker = track_and_check_ip(src_ip, alert.detected_at)
        except Exception:
            pass

    # ---- IoC enrichment (domains + hashes) ------------------------------ #
    for ioc in alert.iocs:
        try:
            if ioc.type == "domain":
                result = check_domain(ioc.value)
                vt_malicious += result.get("malicious_votes", 0)
                vt_total     += sum([
                    result.get("malicious_votes", 0),
                    result.get("harmless_votes", 0),
                    result.get("suspicious_votes", 0),
                ])
            elif ioc.type in ("file_hash", "file_hash_md5", "file_hash_sha1", "file_hash_sha256"):
                result = check_hash(ioc.value)
                vt_malicious += result.get("malicious_votes", 0)
                vt_total     += sum([
                    result.get("malicious_votes", 0),
                    result.get("harmless_votes", 0),
                    result.get("suspicious_votes", 0),
                ])
        except Exception as e:
            logger.warning("VT lookup failed for %s %s: %s", ioc.type, ioc.value, e)

    # ---- Score ---------------------------------------------------------- #
    enrichment_data = {
        "abuse_score":      abuse_score,
        "vt_malicious":     vt_malicious,
        "vt_total":         vt_total if vt_total > 0 else None,
        "geo_country_code": geo_country_code,
    }
    risk_score = float(calculate_risk_score(enrichment_data))

    # ---- Populate enrichment model ------------------------------------- #
    alert.enrichment = EnrichmentData(
        abuse_score      = abuse_score,
        vt_malicious     = vt_malicious,
        vt_total         = vt_total if vt_total > 0 else None,
        geo_country_code = geo_country_code,
        geo_asn_org      = geo_asn_org,
        risk_score       = risk_score,
    )
    alert.status = AlertStatus.TRIAGED

    alert.add_timeline_event(
        actor  = "enrichment.enricher",
        action = "alert_enriched",
        detail = (
            f"abuse={abuse_score}, vt={vt_malicious}/{vt_total}, "
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
    import copy
    alert = copy.deepcopy(alert)

    # Extract primary IP
    network = alert.get("network", {}) or {}
    src_ip  = network.get("src_ip")

    iocs: List[Dict[str, Any]] = alert.get("iocs", []) or []

    abuse_score: Optional[int] = None
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_asn_org: Optional[str] = None
    vt_malicious: int = 0
    vt_total: int = 0

    # ---- IP enrichment -------------------------------------------------- #
    if src_ip:
        try:
            abuse_data = query_ip(src_ip)
            abuse_score = abuse_data.get("abuse_score") or abuse_data.get("abuse_confidence_score")
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed for %s: %s", src_ip, e)

        try:
            geo = get_geolocation(src_ip)
            if geo:
                geo_country      = geo.get("country") or geo.get("country_name")
                geo_country_code = geo.get("country_code") or geo.get("countryCode")
                geo_asn_org      = geo.get("asn") or geo.get("as")
                # Enrich the network subdict
                if "network" not in alert or alert["network"] is None:
                    alert["network"] = {}
                alert["network"]["geo_country"] = geo_country
                alert["network"]["geo_city"]    = geo.get("city")
                alert["network"]["asn"]         = geo_asn_org
        except Exception as e:
            logger.warning("GeoIP lookup failed for %s: %s", src_ip, e)

    # ---- IoC enrichment ------------------------------------------------- #
    for ioc in iocs:
        ioc_type  = ioc.get("type", "")
        ioc_value = ioc.get("value", "")
        try:
            if ioc_type == "domain":
                result = check_domain(ioc_value)
                vt_malicious += result.get("malicious_votes", 0)
                vt_total     += sum([
                    result.get("malicious_votes", 0),
                    result.get("harmless_votes", 0),
                    result.get("suspicious_votes", 0),
                ])
            elif ioc_type in ("file_hash", "file_hash_md5", "file_hash_sha1", "file_hash_sha256", "hash"):
                result = check_hash(ioc_value)
                vt_malicious += result.get("malicious_votes", 0)
                vt_total     += sum([
                    result.get("malicious_votes", 0),
                    result.get("harmless_votes", 0),
                    result.get("suspicious_votes", 0),
                ])
        except Exception as e:
            logger.warning("VT lookup failed for %s %s: %s", ioc_type, ioc_value, e)

    # ---- Score ---------------------------------------------------------- #
    enrichment_data_dict = {
        "abuse_score":      abuse_score if abuse_score is not None else 0,
        "vt_malicious":     vt_malicious,
        "vt_total":         vt_total if vt_total > 0 else 70,
        "geo_country_code": geo_country_code,
    }
    risk_score = float(calculate_risk_score(enrichment_data_dict))

    # ---- Write enrichment block ----------------------------------------- #
    alert["enrichment"] = {
        "abuse_score":      abuse_score,
        "vt_malicious":     vt_malicious,
        "vt_total":         vt_total if vt_total > 0 else None,
        "geo_country_code": geo_country_code,
        "geo_asn_org":      geo_asn_org,
        "risk_score":       risk_score,
    }
    alert["status"] = "triaged"

    # ---- Timeline ------------------------------------------------------- #
    if "timeline" not in alert:
        alert["timeline"] = []
    alert["timeline"].append({
        "ts":     datetime.now(timezone.utc).isoformat(),
        "actor":  "enrichment.enricher",
        "action": "alert_enriched",
        "detail": (
            f"abuse={abuse_score}, vt={vt_malicious}/{vt_total}, "
            f"country={geo_country_code}, risk={risk_score}"
        ),
    })

    return alert
