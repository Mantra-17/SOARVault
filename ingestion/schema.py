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
    src_ip:     Optional[str]  = Field(None, description="Source IP address (IPv4 or IPv6)")
    dst_ip:     Optional[str]  = Field(None, description="Destination IP address (IPv4 or IPv6)")
    src_port:   Optional[int]  = Field(None, description="Source port number")
    dst_port:   Optional[int]  = Field(None, description="Destination port number")
    protocol:   Optional[str]  = Field(None, description="Network protocol (e.g., tcp, udp)")
    bytes_sent: Optional[int]  = Field(None, description="Number of bytes sent")
    bytes_recv: Optional[int]  = Field(None, description="Number of bytes received")
    geo_country: Optional[str] = Field(None, description="Source country code")
    geo_city:    Optional[str] = Field(None, description="Source city")
    asn:         Optional[str] = Field(None, description="Autonomous System Number")

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
    hostname:    Optional[str] = Field(None, description="Hostname of the affected asset")
    ip:          Optional[str] = Field(None, description="Primary IP address of the host")
    os:          Optional[str] = Field(None, description="Operating system version/name")
    cloud_instance_id: Optional[str] = Field(None, description="Cloud provider instance identifier")
    cloud_region:      Optional[str] = Field(None, description="Cloud deployment region")
    cloud_provider:    Optional[str] = Field(None, description="Cloud provider (e.g., aws, gcp, azure)")
    mac_address:       Optional[str] = Field(None, description="Hardware MAC address")
    tags:              List[str]      = Field(default_factory=list, description="Asset classification tags")


class IoC(BaseModel):
    """A single Indicator of Compromise extracted from the alert payload."""
    type:  str          = Field(..., description="Indicator type (ip, domain, file_hash, url, email)")
    value: str          = Field(..., description="The indicator value itself")
    context: Optional[str] = Field(None, description="Contextual explanation for the indicator")

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

    model_config = {
        "json_schema_extra": {
            "example": {
                "alert_id": "123e4567-e89b-12d3-a456-426614174000",
                "type": "brute_force",
                "severity": "high",
                "status": "new",
                "title": "Multiple Failed Logins",
                "detected_at": "2024-03-15T19:00:00Z",
                "network": {"src_ip": "192.168.1.10"}
            }
        }
    }

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

class EnrichmentData(BaseModel):
    abuseipdb_confidence: Optional[int] = None
    virustotal_malicious_votes: Optional[str] = None
    geo: Optional[str] = None
    asn: Optional[str] = None
    first_seen_in_feeds: Optional[str] = None

class TimelineStep(BaseModel):
    step: str
    detail: str
    offset_seconds: float

class Case(BaseModel):
    id: str
    title: str
    severity: str
    ioc: str
    ioc_type: str
    risk_score: int = 0
    mttr_seconds: Optional[float] = None
    playbook: Optional[str] = None
    status: str = "open"
    created_at: str
    enrichment: EnrichmentData = Field(default_factory=EnrichmentData)
    timeline: List[TimelineStep] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
