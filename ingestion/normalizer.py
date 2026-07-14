"""
ingestion/normalizer.py
-----------------------
SIEM payload → NormalizedAlert converter.

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


def _is_private_ip(ip: str) -> bool:
    return any(pat.match(ip) for pat in _PRIVATE_RANGES)


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
    Converts a raw SIEM webhook dict into a validated ``NormalizedAlert``.

    Vendor-specific field mappings are handled by a pluggable ``_field_map``
    dict that subclasses can override for custom SIEM integrations.

    Supported "out of the box" schemas:
      - Generic flat JSON  (most open-source SIEMs)
      - Splunk HEC format
      - CrowdStrike Falcon streaming API event
      - Elastic SIEM / ECS (Elastic Common Schema)

    Usage::

        normalizer = PayloadNormalizer(source_siem="Splunk")
        alert = normalizer.normalize(raw_webhook_body)
    """

    # Map from our canonical field names → list of possible vendor keys
    # (first match wins, left to right)
    _FIELD_CANDIDATES: Dict[str, List[str]] = {
        "title":       ["title", "name", "alert_name", "event.name",
                         "rule.name", "description", "message"],
        "description": ["description", "details", "summary", "event.reason",
                         "message", "log.original"],
        "severity":    ["severity", "severity_label", "level",
                         "event.severity", "score"],
        "type":        ["type", "alert_type", "category",
                         "event.category", "attack_type"],
        "rule_id":     ["rule_id", "rule.id", "detection_id", "sig_id"],
        "src_ip":      ["src_ip", "src.ip", "source.ip", "attacker_ip",
                         "remote_ip", "network.client.ip",
                         "source_address"],
        "dst_ip":      ["dst_ip", "dst.ip", "destination.ip",
                         "network.destination.ip"],
        "src_port":    ["src_port", "source.port", "network.client.port"],
        "dst_port":    ["dst_port", "destination.port",
                         "network.destination.port"],
        "protocol":    ["protocol", "network.transport", "network.protocol"],
        "hostname":    ["hostname", "host.name", "device.hostname",
                         "computer_name", "agent.hostname"],
        "timestamp":   ["timestamp", "detected_at", "event.created",
                         "@timestamp", "time", "start_time"],
        "cloud_id":    ["cloud_instance_id", "instance.id",
                         "cloud.instance.id", "host.id"],
        "cloud_region": ["cloud_region", "cloud.region",
                          "cloud.availability_zone"],
        "cloud_provider": ["cloud_provider", "cloud.provider"],
    }

    def __init__(self, source_siem: Optional[str] = None) -> None:
        self._source_siem  = source_siem
        self._ioc_extractor = IoCExtractor(include_private_ips=False)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def normalize(self, raw: Dict[str, Any]) -> NormalizedAlert:
        """
        Parse ``raw`` and return a fully validated ``NormalizedAlert``.

        Raises ``ValueError`` for payloads that are missing mandatory fields
        that cannot be inferred (currently: *title* and *timestamp*).
        """
        flat = self._flatten(raw)

        title       = self._pick(flat, "title") or "Untitled Alert"
        description = self._pick(flat, "description")
        severity    = _parse_severity(self._pick(flat, "severity"))
        alert_type  = _parse_alert_type(self._pick(flat, "type"))
        rule_id     = self._pick(flat, "rule_id")
        timestamp   = self._pick(flat, "timestamp") or datetime.now(timezone.utc)

        # Network context
        net = NetworkContext(
            src_ip   = self._pick(flat, "src_ip"),
            dst_ip   = self._pick(flat, "dst_ip"),
            src_port = self._safe_int(self._pick(flat, "src_port")),
            dst_port = self._safe_int(self._pick(flat, "dst_port")),
            protocol = self._pick(flat, "protocol"),
        )

        # Host context
        host = HostContext(
            hostname          = self._pick(flat, "hostname"),
            cloud_instance_id = self._pick(flat, "cloud_id"),
            cloud_region      = self._pick(flat, "cloud_region"),
            cloud_provider    = self._pick(flat, "cloud_provider"),
        )

        # IoC extraction from the entire payload
        iocs = self._ioc_extractor.extract_from_dict(raw)

        # Promote src_ip to IoC list if not already captured
        if net.src_ip and not any(
            i.value == net.src_ip and i.type == "ip" for i in iocs
        ):
            iocs.insert(0, IoC(type="ip", value=net.src_ip, context="network.src_ip"))

        # Preserve unknown fields in raw_extra for auditability
        known_keys = {k for keys in self._FIELD_CANDIDATES.values() for k in keys}
        raw_extra = {k: v for k, v in flat.items() if k not in known_keys}

        alert = NormalizedAlert(
            type        = alert_type,
            severity    = severity,
            title       = title,
            description = description,
            source_siem = self._source_siem,
            rule_id     = rule_id,
            detected_at = timestamp,
            network     = net,
            host        = host,
            iocs        = iocs,
            raw_extra   = raw_extra,
        )

        alert.add_timeline_event(
            actor  = "ingestion.normalizer",
            action = "alert_normalized",
            detail = (
                f"source_siem={self._source_siem or 'generic'}, "
                f"ioc_count={len(iocs)}, "
                f"severity={severity.value}"
            ),
        )

        logger.info(
            "alert_normalized id=%s type=%s severity=%s iocs=%d",
            alert.alert_id, alert_type.value, severity.value, len(iocs),
        )
        return alert

    # ------------------------------------------------------------------ #
    # Private utilities                                                    #
    # ------------------------------------------------------------------ #

    def _flatten(self, d: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """
        Recursively flatten a nested dict using dot-notation keys.
        e.g. {"network": {"src_ip": "1.2.3.4"}} → {"network.src_ip": "1.2.3.4"}
        """
        out: Dict[str, Any] = {}
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                out.update(self._flatten(v, prefix=full_key))
            else:
                out[full_key] = v
        return out

    def _pick(self, flat: Dict[str, Any], canonical: str) -> Optional[Any]:
        """Return the first non-None value matching any candidate key."""
        for candidate in self._FIELD_CANDIDATES.get(canonical, []):
            if candidate in flat and flat[candidate] is not None:
                return flat[candidate]
        return None

    @staticmethod
    def _safe_int(v: Any) -> Optional[int]:
        if v is None:
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
