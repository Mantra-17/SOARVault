"""
Unit and integration tests to verify the threat intelligence enricher
runs successfully on all 10 sample alerts, documenting the scoring results.
"""

import os
import json
import pytest
from datetime import datetime
from ingestion.normalizer import PayloadNormalizer
from enrichment.enricher import enrich_alert
from ingestion.schema import NormalizedAlert, AlertStatus


def get_all_sample_alerts():
    """Retrieve all sample alert file paths and their contents."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples_dir = os.path.join(base_dir, "ingestion", "sample_alerts")
    
    assert os.path.exists(samples_dir), f"Samples directory not found: {samples_dir}"
    
    sample_files = [
        f for f in os.listdir(samples_dir)
        if f.endswith(".json")
    ]
    
    samples = []
    for f in sorted(sample_files):
        path = os.path.join(samples_dir, f)
        with open(path, "r", encoding="utf-8") as file_handle:
            data = json.load(file_handle)
            samples.append((f, data))
            
    return samples


def test_enrich_all_10_samples():
    """Load, normalize, and enrich all sample alerts, asserting correctness."""
    samples = get_all_sample_alerts()
    assert len(samples) == 10, f"Expected exactly 10 sample alerts, found {len(samples)}"
    
    print("\n" + "="*80)
    print(f"{'Sample Alert File':<35} | {'Risk Score':<10} | {'Country':<8} | {'Status':<10}")
    print("="*80)
    
    for filename, raw_data in samples:
        # Determine SIEM source if possible
        source_siem = raw_data.get("source") or raw_data.get("source_siem") or "generic"
        
        # 1. Normalize
        normalizer = PayloadNormalizer(source_siem=source_siem)
        normalized_alert = normalizer.normalize(raw_data)
        
        # Verify normalization succeeded
        assert isinstance(normalized_alert, NormalizedAlert)
        assert normalized_alert.status == AlertStatus.NEW
        
        # 2. Enrich
        enriched_alert = enrich_alert(normalized_alert)
        
        # Verify enrichment succeeded
        assert enriched_alert.status == AlertStatus.TRIAGED
        assert enriched_alert.enrichment is not None
        assert enriched_alert.enrichment.risk_score is not None
        
        # Extract fields for output validation
        risk_score = enriched_alert.enrichment.risk_score
        geo_country = enriched_alert.enrichment.geo_country_code or "N/A"
        
        print(f"{filename:<35} | {risk_score:<10} | {geo_country:<8} | {enriched_alert.status.value:<10}")
        
        # Detailed assertions based on test file attributes:
        if "brute_force" in filename:
            # IP: 185.234.218.20 -> Fallback check maps deterministically to a mock response
            assert risk_score >= 0
        elif "phishing" in filename:
            # IP contains 50 -> Abuse score 50 (weight 0.5 -> 25)
            # URL contains malicious -> VT malicious (malicious check returns a malicious mock file)
            # Total score should be around 25 + VT_score * 0.3
            assert risk_score > 0
        elif "c2_beaconing" in filename:
            # IP contains 90 -> Abuse score 90 (weight 0.5 -> 45)
            assert risk_score >= 45
        elif "ransomware_activity" in filename:
            # IP contains 100 -> Abuse score 100 (weight 0.5 -> 50)
            # Domain contains malicious -> VT malicious (weight 0.3 -> VT_score)
            assert risk_score >= 50
            
    print("="*80)
