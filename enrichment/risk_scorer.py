"""
Risk scorer module.
Calculates a composite risk score from enrichment data.
"""

from typing import Any, Dict, Optional

# List of high-risk countries (ISO 3166-1 alpha-2 codes)
HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "SY"}

def calculate_risk_score(enrichment_data: Any) -> int:
    """
    Calculate a composite risk score (0-100) based on enrichment data.
    
    Formula:
      score = abuse_score * 0.5 + vt_malicious * 0.3 + country_risk * 0.2
      
    Where:
      - abuse_score: confidence score from AbuseIPDB (0-100)
      - vt_malicious: normalized VirusTotal malicious engine score (0-100)
      - country_risk: risk score based on country code (0 or 100)
    """
    if enrichment_data is None:
        return 0

    # Helper to get values from dict or object safely
    def _get_val(data: Any, name: str, default: Any = None) -> Any:
        val = None
        if isinstance(data, dict):
            val = data.get(name)
        else:
            val = getattr(data, name, None)
        return val if val is not None else default

    # 1. Get Abuse Score (0-100)
    abuse_score = _get_val(enrichment_data, "abuse_score", 0)
    abuse_score = max(0.0, min(100.0, float(abuse_score)))

    # 2. Get VirusTotal Score (0-100)
    # Check if a pre-computed vt_score exists
    vt_score = _get_val(enrichment_data, "vt_score", None)
    if vt_score is None:
        vt_malicious_val = _get_val(enrichment_data, "vt_malicious", 0)
        vt_total_val = _get_val(enrichment_data, "vt_total", 0)
        
        if vt_total_val > 0:
            vt_score = (vt_malicious_val / vt_total_val) * 100.0
        else:
            if vt_malicious_val > 0:
                # Default to 70 engines if total is not provided
                vt_score = (vt_malicious_val / 70.0) * 100.0
            else:
                vt_score = 0.0
                
    vt_score = max(0.0, min(100.0, float(vt_score)))

    # 3. Get Country Risk Score (0-100)
    country_risk_score = _get_val(enrichment_data, "country_risk", None)
    if country_risk_score is None:
        country_code = _get_val(enrichment_data, "geo_country_code", None)
        if country_code is None:
            country_code = _get_val(enrichment_data, "country_code", None)
        if country_code is None:
            country_code = _get_val(enrichment_data, "country", None)
            
        if isinstance(country_code, str):
            country_code = country_code.strip().upper()
            
        if country_code in HIGH_RISK_COUNTRIES:
            country_risk_score = 100.0
        else:
            country_risk_score = 0.0
            
    country_risk_score = max(0.0, min(100.0, float(country_risk_score)))

    # Calculate final weighted score
    final_score = (abuse_score * 0.5) + (vt_score * 0.3) + (country_risk_score * 0.2)
    
    # Add +20 automatically if this is a repeat attacker
    repeat_attacker = _get_val(enrichment_data, "repeat_attacker", False)
    if repeat_attacker:
        final_score += 20.0

    # Ensure bounds and round to nearest integer
    return int(round(max(0.0, min(100.0, final_score))))


def get_risk_label(score: float) -> str:
    """
    Get the risk level label based on the score.
    
    Risk levels:
      - CRITICAL: 81-100
      - HIGH: 61-80
      - MEDIUM: 41-60
      - LOW: 0-40
    """
    val = int(round(score))
    if val >= 81:
        return "CRITICAL"
    elif val >= 61:
        return "HIGH"
    elif val >= 41:
        return "MEDIUM"
    else:
        return "LOW"
