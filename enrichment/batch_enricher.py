"""enrichment/batch_enricher.py
-----------------------------
Concurrent IP enrichment engine using asyncio and Redis caching.
Fulfills Day 19 requirements.
"""

import asyncio
import logging
from typing import Any, Dict, List

from enrichment.abuseipdb import check_ip_async
from enrichment.geoip import get_geoip_async
from enrichment.risk_scorer import calculate_risk_score, get_risk_label
from enrichment.false_positive_detector import analyze_false_positive

logger = logging.getLogger(__name__)


async def enrich_single_ip_with_retries(ip: str, retries: int = 3, backoff: float = 1.0) -> Dict[str, Any]:
    """Enriches a single IP address with retry logic and exponential backoff.

    Args:
        ip: The IP address to enrich.
        retries: Number of retry attempts for API calls.
        backoff: Baseline time to back off (seconds) for exponential retry.

    Returns:
        A dictionary containing the enrichment details for the IP.
    """
    for attempt in range(1, retries + 1):
        try:
            # Query GeoIP and AbuseIPDB concurrently
            geo_task = get_geoip_async(ip)
            abuse_task = check_ip_async(ip)
            
            geo, abuse = await asyncio.gather(geo_task, abuse_task)
            
            # Check for errors in return dicts
            if geo and geo.get("error") and attempt < retries:
                raise RuntimeWarning(f"GeoIP error: {geo.get('error')}")
            
            # Extract fields
            country_code = geo.get("country_code") or abuse.get("country") or "Unknown"
            isp = geo.get("isp") or abuse.get("isp") or "Unknown ISP"
            abuse_score = abuse.get("abuse_score", 0)
            
            # VirusTotal mock setup for scoring consistency
            vt_malicious = 0
            vt_total = 70
            
            # Composite risk calculation
            score_data = {
                "abuse_score": abuse_score,
                "vt_malicious": vt_malicious,
                "vt_total": vt_total,
                "geo_country_code": country_code,
            }
            risk_score = calculate_risk_score(score_data)
            risk_level = get_risk_label(risk_score)
            
            # False Positive Analysis
            is_fp, fp_reason = analyze_false_positive(
                ip=ip,
                abuse_score=abuse_score,
                vt_malicious=vt_malicious,
                vt_total=vt_total,
                isp=isp
            )
            
            return {
                "ip": ip,
                "status": "success",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "country_code": country_code,
                "isp": isp,
                "false_positive": is_fp,
                "false_positive_explanation": fp_reason,
                "error": ""
            }
            
        except Exception as e:
            logger.warning("Attempt %d to enrich IP %s failed: %s", attempt, ip, e)
            if attempt == retries:
                return {
                    "ip": ip,
                    "status": "failed",
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "country_code": "Unknown",
                    "isp": "Unknown ISP",
                    "false_positive": False,
                    "false_positive_explanation": "",
                    "error": str(e)
                }
            # Exponential backoff
            await asyncio.sleep(backoff * (2 ** (attempt - 1)))


async def enrich_ips_concurrently(ips: List[str]) -> Dict[str, Any]:
    """Enriches multiple IP addresses concurrently using asyncio.gather.

    Args:
        ips: A list of IP addresses.

    Returns:
        An aggregated summary dict of enrichment results.
    """
    if not ips:
        return {
            "total_requested": 0,
            "successful": 0,
            "failed": 0,
            "results": {}
        }
        
    tasks = [enrich_single_ip_with_retries(ip) for ip in ips]
    results_list = await asyncio.gather(*tasks)
    
    successful_count = sum(1 for r in results_list if r["status"] == "success")
    failed_count = sum(1 for r in results_list if r["status"] == "failed")
    
    results_map = {r["ip"]: r for r in results_list}
    
    return {
        "total_requested": len(ips),
        "successful": successful_count,
        "failed": failed_count,
        "results": results_map
    }
