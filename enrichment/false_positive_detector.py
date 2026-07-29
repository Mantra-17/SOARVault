"""enrichment/false_positive_detector.py
----------------------------------------
False-positive detection heuristics for SOARVault.
"""

from typing import Any, Dict, Tuple

# List of trusted ISPs and organizations that are often flag targets but generally safe
TRUSTED_ISPS = [
    "google",
    "cloudflare",
    "microsoft",
    "amazon",
    "fastly",
    "akamai",
    "quad9",
    "cisco",
    "level 3",
    "apple",
    "oracle",
]

# Known public recursive DNS resolvers that trigger volume alerts but are benign
KNOWN_PUBLIC_RESOLVERS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "Cisco OpenDNS",
    "208.67.220.220": "Cisco OpenDNS",
}


def analyze_false_positive(
    ip: str,
    abuse_score: int,
    vt_malicious: int,
    vt_total: int,
    isp: str,
) -> Tuple[bool, str]:
    """Analyzes threat data to flag safe indicators as Potential False Positives.

    Args:
        ip: The IP address to evaluate.
        abuse_score: The AbuseIPDB abuse confidence score (0-100).
        vt_malicious: The count of malicious votes on VirusTotal.
        vt_total: The total count of analysis engine votes on VirusTotal.
        isp: The ISP or organization name of the IP address.

    Returns:
        A tuple of (is_false_positive, explanation).
    """
    # Case 1: Known public resolvers
    if ip in KNOWN_PUBLIC_RESOLVERS:
        resolver_name = KNOWN_PUBLIC_RESOLVERS[ip]
        return True, f"IP is a well-known public recursive DNS resolver ({resolver_name}). Highly unlikely to be a malicious origin."

    # Case 2: Clean reputation and trusted ISP/Organization
    isp_lower = isp.lower() if isp else ""
    is_trusted_isp = any(trusted in isp_lower for trusted in TRUSTED_ISPS)

    # If it's a trusted infrastructure and has zero malicious indicators
    if is_trusted_isp and abuse_score <= 10 and vt_malicious == 0:
        return True, f"IP belongs to a trusted infrastructure provider ({isp}) with low abuse score ({abuse_score}) and no VirusTotal malicious detections."

    # Case 3: High harmless votes but zero malicious votes, even with moderate abuse reports
    # (Sometimes safe IPs get reported due to misconfigurations)
    if vt_malicious == 0 and vt_total >= 10 and abuse_score < 30:
        return True, f"VirusTotal shows zero malicious engine votes against {vt_total} harmless votes, indicating a low-risk profile despite minor abuse reports ({abuse_score})."

    return False, ""
