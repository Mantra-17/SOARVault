import random
from datetime import datetime
from ingestion.schema import RawAlert, NormalizedAlert
from ingestion.database import get_redis_client

Raw SIEM webhook bodies arrive in wildly different shapes depending on the
vendor (Splunk, QRadar, Elastic SIEM, CrowdStrike, etc.).  This module
provides:

  1. ``IoC_Extractor``     – regex-based extractor that scans any text blob
                             or JSON dict for IP addresses, domains, file
                             hashes and URLs.
  2. ``PayloadNormalizer`` – vendor-agnostic normaliser that maps a raw dict
                             to a fully-validated ``NormalizedAlert`` instance.

Design principle: all lossy decisions (e.g. "which field is the severity?")
are made here in one place, never scattered across playbooks.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from .schema import (
    AlertType,
    HostContext,
    IoC,
    NetworkContext,
    NormalizedAlert,
    Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regex patterns for IoC extraction
# ---------------------------------------------------------------------------

# IPv4 only (IPv6 support coming in a later iteration)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# RFC 1123 domain — must have a valid TLD of 2+ characters
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)

# MD5 / SHA-1 / SHA-256 file hashes
_RE_HASH_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_HASH_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_HASH_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Bare URLs (http/https)
_RE_URL = re.compile(
    r"https?://[^\s\"'<>]+"
)

# Private / loopback ranges — exclude from IoC lists
_PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),   # link-local
    re.compile(r"^::1$"),         # IPv6 loopback
]

# Common internal-use domain suffixes to skip
_INTERNAL_TLDS = {"local", "internal", "corp", "lan", "home", "localdomain"}


@lru_cache(maxsize=1024)
def _is_private_ip(ip: str) -> bool:
    return any(pat.match(ip) for pat in _PRIVATE_RANGES)


@lru_cache(maxsize=1024)
def _is_internal_domain(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in _INTERNAL_TLDS


# ---------------------------------------------------------------------------
# IoC Extractor
# ---------------------------------------------------------------------------

class IoCExtractor:
    """
    Scans a free-form string (or recursively a dict) for indicators of
    compromise and returns a deduplicated list of ``IoC`` objects.

    Usage::

        extractor = IoCExtractor()
        iocs = extractor.extract_from_text("attack from 185.234.218.20 via evil.ru")
        iocs = extractor.extract_from_dict(raw_payload)
    """

    def __init__(
        self,
        include_private_ips: bool = False,
        include_internal_domains: bool = False,
    ) -> None:
        self._include_private   = include_private_ips
        self._include_internal  = include_internal_domains
        self._seen: set          = set()   # deduplication key: (type, value)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def extract_from_text(self, text: str, context: str = "") -> List[IoC]:
        """Extract all IoC types from a plain-text string."""
        self._seen = set()
        results: List[IoC] = []

        results.extend(self._extract_ips(text, context))
        results.extend(self._extract_hashes(text, context))
        results.extend(self._extract_urls(text, context))
        # Extract domains only from text not already captured as part of URLs
        stripped = _RE_URL.sub("", text)
        results.extend(self._extract_domains(stripped, context))

        return results

    def extract_from_dict(self, payload: Dict[str, Any]) -> List[IoC]:
        """
        Recursively flatten a SIEM payload dict and extract IoCs from every
        string value.
        """
        self._seen = set()
        return self._recurse_dict(payload, path="")

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _add(self, ioc_type: str, value: str, context: str, out: List[IoC]) -> None:
        key = (ioc_type, value.lower())
        if key not in self._seen:
            self._seen.add(key)
            out.append(IoC(type=ioc_type, value=value, context=context or None))

    def _extract_ips(self, text: str, context: str) -> List[IoC]:
        out: List[IoC] = []
        for match in _RE_IPV4.finditer(text):
            ip = match.group()
            if not self._include_private and _is_private_ip(ip):
                continue
            self._add("ip", ip, context, out)
        return out

    def _extract_domains(self, text: str, context: str) -> List[IoC]:
        out: List[IoC] = []
        for match in _RE_DOMAIN.finditer(text):
            domain = match.group().lower()
            if not self._include_internal and _is_internal_domain(domain):
                continue
            self._add("domain", domain, context, out)
        return out

    def _extract_hashes(self, text: str, context: str) -> List[IoC]:
        out: List[IoC] = []
        # Order matters: try longest first to avoid false sub-matches
        for pattern, hash_type in [
            (_RE_HASH_SHA256, "file_hash_sha256"),
            (_RE_HASH_SHA1,   "file_hash_sha1"),
            (_RE_HASH_MD5,    "file_hash_md5"),
        ]:
            for match in pattern.finditer(text):
                self._add(hash_type, match.group().lower(), context, out)
        return out

    def _extract_urls(self, text: str, context: str) -> List[IoC]:
        out: List[IoC] = []
        for match in _RE_URL.finditer(text):
            self._add("url", match.group(), context, out)
        return out

    def _recurse_dict(self, obj: Any, path: str) -> List[IoC]:
        out: List[IoC] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                out.extend(self._recurse_dict(v, path=f"{path}.{k}" if path else k))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                out.extend(self._recurse_dict(item, path=f"{path}[{i}]"))
        elif isinstance(obj, str):
            out.extend(self.extract_from_text(obj, context=path))
        return out


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

# Numeric severity thresholds (as used by various SIEMs / CVSS)
_SEVERITY_NUM_MAP: List[Tuple[int, Severity]] = [
    (9,  Severity.CRITICAL),
    (7,  Severity.HIGH),
    (4,  Severity.MEDIUM),
    (1,  Severity.LOW),
    (0,  Severity.INFO),
]

_SEVERITY_STR_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit":     Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "med":      Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "informational": Severity.INFO,
}

_ALERT_TYPE_STR_MAP: Dict[str, AlertType] = {
    "brute_force":        AlertType.BRUTE_FORCE,
    "brute force":        AlertType.BRUTE_FORCE,
    "ssh_brute_force":    AlertType.BRUTE_FORCE,
    "rdp_brute_force":    AlertType.BRUTE_FORCE,
    "malware":            AlertType.MALWARE,
    "ransomware":         AlertType.MALWARE,
    "trojan":             AlertType.MALWARE,
    "data_exfiltration":  AlertType.DATA_EXFIL,
    "data exfil":         AlertType.DATA_EXFIL,
    "exfiltration":       AlertType.DATA_EXFIL,
    "ddos":               AlertType.DDOS,
    "dos":                AlertType.DDOS,
    "flood":              AlertType.DDOS,
    "insider_threat":     AlertType.INSIDER_THREAT,
    "insider threat":     AlertType.INSIDER_THREAT,
    "policy_violation":   AlertType.INSIDER_THREAT,
    "phishing":           AlertType.PHISHING,
    "spear_phishing":     AlertType.PHISHING,
    "lateral_movement":   AlertType.LATERAL_MOVE,
    "lateral movement":   AlertType.LATERAL_MOVE,
    "pass_the_hash":      AlertType.LATERAL_MOVE,
}


def _parse_severity(raw: Any) -> Severity:
    if isinstance(raw, (int, float)):
        for threshold, sev in _SEVERITY_NUM_MAP:
            if raw >= threshold:
                return sev
        return Severity.INFO
    if isinstance(raw, str):
        return _SEVERITY_STR_MAP.get(raw.strip().lower(), Severity.MEDIUM)
    return Severity.MEDIUM


def _parse_alert_type(raw: Any) -> AlertType:
    if isinstance(raw, str):
        return _ALERT_TYPE_STR_MAP.get(raw.strip().lower(), AlertType.UNKNOWN)
    return AlertType.UNKNOWN


# ---------------------------------------------------------------------------
# Payload Normalizer
# ---------------------------------------------------------------------------

class PayloadNormalizer:
    """
    Normalizes a vendor-specific raw alert into a standardized format.
    Generates a unique alert ID using Redis counters (with a random fallback).
    """
    db = get_redis_client()
    try:
        alert_seq = db.incr("counters:alert_id")
        # Ensure we match standard mock IDs format (around 88000+)
        if alert_seq < 88000:
            db.set("counters:alert_id", 88200)
            alert_seq = 88200
    except Exception:
        alert_seq = random.randint(88200, 89000)
        
    alert_id = f"ALRT-{alert_seq}"
    received_at = raw.received_at or datetime.utcnow().isoformat()
    
    # Standardize severity
    severity = raw.severity.lower().strip()
    if severity not in ("critical", "high", "medium", "low"):
        severity = "medium"
        
    return NormalizedAlert(
        id=alert_id,
        title=raw.rule_name,
        source=raw.source,
        severity=severity,
        ioc_value=raw.ioc_value,
        ioc_type=raw.ioc_type.lower().strip(),
        received_at=received_at,
        enrichment_status="queued"
    )
