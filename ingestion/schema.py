from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

class RawAlert(BaseModel):
    source: str
    rule_name: str
    severity: str
    ioc_type: str
    ioc_value: str
    raw_details: Dict[str, Any] = Field(default_factory=dict)
    received_at: Optional[str] = None

class NormalizedAlert(BaseModel):
    id: str
    title: str
    source: str
    severity: str
    ioc_value: str
    ioc_type: str
    received_at: str
    enrichment_status: str = "queued"  # queued, in_progress, complete, failed

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
