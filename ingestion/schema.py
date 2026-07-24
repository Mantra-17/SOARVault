"""
ingestion/schema.py
-------------------
Canonical Pydantic models for every alert type that SOARVault can ingest.

All raw SIEM payloads are normalised into one of these models before being
handed off to enrichment or playbook execution.  Using Pydantic v2 means we
get automatic type coercion, OpenAPI doc generation, and a single source of
truth for field validation across the entire engine.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerated constants
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """CVSS-aligned four-tier severity classification."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class AlertType(str, Enum):
    """Supported attack-vector categories understood by the playbook engine."""
    BRUTE_FORCE     = "brute_force"
    MALWARE         = "malware"
    DATA_EXFIL      = "data_exfiltration"
    DDOS            = "ddos"
    INSIDER_THREAT  = "insider_threat"
    PHISHING        = "phishing"
    LATERAL_MOVE    = "lateral_movement"
    UNKNOWN         = "unknown"


class AlertStatus(str, Enum):
    """Lifecycle state of an alert through the SOAR pipeline."""
    NEW         = "new"          # just ingested, not yet processed
    ENRICHING   = "enriching"    # threat-intel queries in flight
    TRIAGED     = "triaged"      # enrichment complete, awaiting playbook
    CONTAINED   = "contained"    # playbook executed successfully
    ESCALATED   = "escalated"    # requires human analyst review
    CLOSED      = "closed"       # analyst confirmed resolution
    FALSE_POS   = "false_positive"


# ---------------------------------------------------------------------------
# Embedded sub-models
# ---------------------------------------------------------------------------

class NetworkContext(BaseModel):
    """Optional network-layer metadata attached to an alert."""
    src_ip:     Optional[str]  = None
    dst_ip:     Optional[str]  = None
    src_port:   Optional[int]  = None
    dst_port:   Optional[int]  = None
    protocol:   Optional[str]  = None
    bytes_sent: Optional[int]  = None
    bytes_recv: Optional[int]  = None
    geo_country: Optional[str] = None
    geo_city:    Optional[str] = None
    asn:         Optional[str] = None

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def validate_ip(cls, v: Any) -> Optional[str]:
        if v is None:
            return v
        # Accept both IPv4 and IPv6 — lightweight sanity check
        ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
        s = str(v).strip()
        if not (ipv4.match(s) or ipv6.match(s)):
            raise ValueError(f"'{s}' is not a valid IP address")
        return s


class HostContext(BaseModel):
    """Endpoint / workload metadata associated with the affected asset."""
    hostname:    Optional[str] = None
    ip:          Optional[str] = None
    os:          Optional[str] = None
    cloud_instance_id: Optional[str] = None   # e.g. AWS EC2 instance-id
    cloud_region:      Optional[str] = None
    cloud_provider:    Optional[str] = None   # aws | gcp | azure
    mac_address:       Optional[str] = None
    tags:              List[str]      = Field(default_factory=list)


class IoC(BaseModel):
    """A single Indicator of Compromise extracted from the alert payload."""
    type:  str          # ip | domain | file_hash | url | email
    value: str
    context: Optional[str] = None   # e.g. "source IP of brute-force attempt"

    # --- normalise hash strings to lower-case hex ---
    @field_validator("value", mode="before")
    @classmethod
    def normalise_value(cls, v: Any) -> str:
        return str(v).strip()


class EnrichmentData(BaseModel):
    """
    Container for external threat-intel data added by the enrichment layer.
    Populated by enrichment/enricher.py *after* ingestion normalisation.
    """
    abuse_score:      Optional[int]   = None   # 0-100 from AbuseIPDB
    vt_malicious:     Optional[int]   = None   # malicious engine count from VT
    vt_total:         Optional[int]   = None   # total VT engine count
    is_tor_exit:      Optional[bool]  = None
    is_vpn:           Optional[bool]  = None
    threat_feeds:     List[str]       = Field(default_factory=list)
    geo_country_code: Optional[str]   = None
    geo_asn_org:      Optional[str]   = None
    repeat_attacker:  Optional[bool]  = None
    # Composite risk score computed by risk_scorer.py  (0.0 – 100.0)
    risk_score:       Optional[float] = None


# ---------------------------------------------------------------------------
# Core canonical alert model
# ---------------------------------------------------------------------------

class NormalizedAlert(BaseModel):
    """
    The single canonical data structure used throughout SOARVault.

    Every ingested SIEM payload is parsed and validated into this model by
    ingestion/normalizer.py before anything else touches it.
    """

    # Identifiers
    alert_id:    UUID          = Field(default_factory=uuid4)
    correlation_id: Optional[str] = None          # SIEM-supplied correlation key

    # Classification
    type:        AlertType     = AlertType.UNKNOWN
    severity:    Severity      = Severity.MEDIUM
    status:      AlertStatus   = AlertStatus.NEW

    # Human-readable labels
    title:       str
    description: Optional[str] = None
    source_siem: Optional[str] = None             # e.g. "Splunk", "QRadar", "CrowdStrike"
    rule_id:     Optional[str] = None             # SIEM detection rule that fired

    # Timestamps (always stored as UTC-aware datetimes)
    detected_at:  datetime
    ingested_at:  datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Context sub-objects
    network:     Optional[NetworkContext] = None
    host:        Optional[HostContext]    = None

    # IoCs extracted during normalisation
    iocs:        List[IoC]               = Field(default_factory=list)

    # Enrichment blob (filled in by enrichment layer)
    enrichment:  Optional[EnrichmentData] = None

    # Arbitrary key-value store for SIEM-specific extra fields
    raw_extra:   Dict[str, Any]          = Field(default_factory=dict)

    # Audit trail populated by the playbook engine
    timeline:    List[Dict[str, Any]]    = Field(default_factory=list)

    # ----- validators -------------------------------------------------------

    @field_validator("detected_at", mode="before")
    @classmethod
    def parse_detected_at(cls, v: Any) -> datetime:
        """
        Accept ISO-8601 strings with or without timezone info, Unix epoch
        integers, or datetime objects.  Always returns a UTC-aware datetime.
        """
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=timezone.utc)
        if isinstance(v, str):
            # Normalise common SIEM variants: "2024-01-15T10:30:00Z",
            # "2024-01-15 10:30:00+05:30", "2024-01-15T10:30:00.000Z"
            s = v.strip().replace(" ", "T")
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(s)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                raise ValueError(
                    f"Cannot parse timestamp '{v}'. "
                    "Expected ISO-8601, Unix epoch int, or datetime object."
                )
        raise TypeError(f"Unsupported timestamp type: {type(v)}")

    @model_validator(mode="after")
    def ensure_utc(self) -> "NormalizedAlert":
        """Convert any non-UTC aware timestamps to UTC at model creation time."""
        if self.detected_at.utcoffset() is not None:
            self.detected_at = self.detected_at.astimezone(timezone.utc)
        return self

    # ----- helpers ----------------------------------------------------------

    def add_timeline_event(self, actor: str, action: str, detail: str = "") -> None:
        """Append a timestamped event to the alert timeline (audit trail)."""
        self.timeline.append(
            {
                "ts":     datetime.now(timezone.utc).isoformat(),
                "actor":  actor,
                "action": action,
                "detail": detail,
            }
        )

    def primary_ip(self) -> Optional[str]:
        """Return the most relevant attacking IP for enrichment lookups."""
        # Prefer network src_ip, fall back to any IP-type IoC
        if self.network and self.network.src_ip:
            return self.network.src_ip
        for ioc in self.iocs:
            if ioc.type == "ip":
                return ioc.value
        return None

    def to_summary(self) -> Dict[str, Any]:
        """Lightweight dict suitable for dashboard list views."""
        return {
            "alert_id":   str(self.alert_id),
            "type":       self.type.value,
            "severity":   self.severity.value,
            "status":     self.status.value,
            "title":      self.title,
            "source_ip":  self.primary_ip(),
            "risk_score": self.enrichment.risk_score if self.enrichment else None,
            "detected_at": self.detected_at.isoformat(),
        }
