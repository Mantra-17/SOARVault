"""
enrichment/risk_scorer.py
--------------------------
Composite risk score calculator for SOARVault.

Accepts either the original 3-argument call signature (for backward compat
with the playbook engine) or a modern dict / EnrichmentData object.

Score formula (dict/object mode):
    score = (abuse_score * 0.5)
           + (vt_ratio * 100 * 0.3)
           + (country_risk * 0.2)
    clamped to [0, 100] and rounded to nearest int.

Country-risk lookup is based on Tier-1 intelligence agency classifications
of high-risk nation-state cyber-threat origins.
"""

from __future__ import annotations

from typing import Any, Optional, Union

# ---------------------------------------------------------------------------
# Country risk map  (0 = no risk, 75 = elevated, 100 = highest risk)
# ---------------------------------------------------------------------------
_COUNTRY_RISK: dict[str, int] = {
    # Highest risk — active state-sponsored threat actors
    "KP": 100, "IR": 100,
    # High risk
    "RU": 75,  "CN": 75,  "BY": 75,
    # Elevated risk
    "SY": 50,  "VE": 50,  "CU": 50,  "MM": 50,
    # All others — baseline 0 (score driven purely by AbuseIPDB + VT)
}

_DEFAULT_VT_TOTAL = 70  # default denominator when vt_total is missing


# ---------------------------------------------------------------------------
# Public API — two call signatures
# ---------------------------------------------------------------------------

def calculate_risk_score(
    data_or_severity: Any = None,
    abuse_score: Optional[int] = None,
    vt_votes: Optional[Union[str, int]] = None,
) -> int:
    """
    Calculate a composite risk score (0–100).

    **Signature 1 — dict / EnrichmentData (preferred):**
        score = calculate_risk_score({
            "abuse_score": 80,
            "vt_malicious": 10,
            "vt_total": 10,           # optional, defaults to 70
            "geo_country_code": "RU", # or "country_code", "country"
            "country_risk": 75,       # optional override
        })

    **Signature 2 — legacy 3-positional args (backward compat):**
        score = calculate_risk_score("high", 50, "36/72")
    """
    # Detect call signature
    if data_or_severity is None:
        return 0

    if isinstance(data_or_severity, str):
        # Legacy mode: (severity_str, abuse_int, vt_str)
        return _legacy_score(data_or_severity, abuse_score, vt_votes)

    # Modern dict / object mode
    return _dict_score(data_or_severity)


def get_risk_label(score: int) -> str:
    """
    Convert a numeric risk score (0-100) to a human-readable uppercase label.
    Thresholds align with PlaybookEngine trigger conditions.

        >= 80  → CRITICAL  (triggers isolate-ec2-and-block-ip)
        >= 60  → HIGH      (triggers block-ip-firewall)
        >= 40  → MEDIUM
        >= 20  → LOW
         < 20  → LOW       (treat info as low for dashboard display)
    """
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _dict_score(data: Any) -> int:
    """Score from a dict or Pydantic model with enrichment fields."""
    if not data:
        return 0

    # Support both dict and Pydantic model (attribute access)
    def _get(key: str, default: Any = None) -> Any:
        if isinstance(data, dict):
            return data.get(key, default)
        return getattr(data, key, default)

    abuse = float(_get("abuse_score") or 0)

    vt_malicious = float(_get("vt_malicious") or 0)
    vt_total     = float(_get("vt_total") or _DEFAULT_VT_TOTAL)
    vt_ratio     = vt_malicious / max(vt_total, 1)

    # Country risk: explicit override > geo_country_code > country_code > country
    country_risk = _get("country_risk")
    if country_risk is None:
        cc = (
            _get("geo_country_code")
            or _get("country_code")
            or _get("country")
            or ""
        )
        if isinstance(cc, str):
            cc = cc.strip().upper()
        country_risk = _COUNTRY_RISK.get(cc, 0)

    score = (abuse * 0.5) + (vt_ratio * 100 * 0.3) + (float(country_risk) * 0.2)
    return max(0, min(100, round(score)))


def _legacy_score(
    severity: str,
    abuse_score: Optional[int],
    vt_votes: Optional[Union[str, int]],
) -> int:
    """
    Original 3-arg signature used by the playbook engine.

    Base score from severity + bonus from AbuseIPDB + bonus from VirusTotal.
    """
    severity_map = {
        "critical": 65,
        "high":     45,
        "medium":   25,
        "low":      10,
    }
    score = severity_map.get(severity.lower() if severity else "", 25)

    if abuse_score is not None:
        score += int(abuse_score * 0.2)   # up to +20

    if vt_votes is not None:
        malicious, total = 0, 72
        if isinstance(vt_votes, str) and "/" in vt_votes:
            try:
                parts    = vt_votes.split("/")
                malicious = int(parts[0])
                total     = max(int(parts[1]), 1)
            except ValueError:
                pass
        elif isinstance(vt_votes, (int, float)):
            malicious = int(vt_votes)
        ratio  = malicious / total if total > 0 else 0
        score += int(ratio * 25)          # up to +25

    return max(0, min(100, score))
