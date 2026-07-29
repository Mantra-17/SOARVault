"""Run enrichment against all sample alerts and generate a performance and accuracy report.

Fulfills Day 16 requirements.
"""

import os
import json
import time
from datetime import datetime, timezone
from ingestion.normalizer import PayloadNormalizer
from enrichment.enricher import enrich_alert
from enrichment.risk_scorer import get_risk_label
from ingestion.schema import NormalizedAlert, AlertStatus


def get_all_sample_alerts():
    """Retrieve all sample alerts from the ingestion/sample_alerts folder."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples_dir = os.path.join(base_dir, "ingestion", "sample_alerts")
    
    if not os.path.exists(samples_dir):
        return []
    
    sample_files = [f for f in os.listdir(samples_dir) if f.endswith(".json")]
    samples = []
    for f in sorted(sample_files):
        path = os.path.join(samples_dir, f)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                samples.append((f, data))
        except Exception as e:
            print(f"Error loading {f}: {e}")
            
    return samples


def main():
    samples = get_all_sample_alerts()
    if not samples:
        print("No sample alerts found!")
        return

    total = len(samples)
    successful = 0
    failed = 0
    total_risk = 0.0
    risk_categories = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    details = []

    print(f"Running enrichment against {total} sample alerts...")

    for filename, raw_data in samples:
        source_siem = raw_data.get("source") or raw_data.get("source_siem") or "generic"
        start_time = time.perf_counter()
        
        try:
            # 1. Normalize
            normalizer = PayloadNormalizer(source_siem=source_siem)
            normalized_alert = normalizer.normalize(raw_data)
            
            # 2. Enrich
            enriched_alert = enrich_alert(normalized_alert)
            
            latency = (time.perf_counter() - start_time) * 1000.0  # ms
            
            # Extract score and metrics
            risk_score = enriched_alert.enrichment.risk_score
            risk_lbl = get_risk_label(int(risk_score))
            country = enriched_alert.enrichment.geo_country_code or "N/A"
            abuse_score = enriched_alert.enrichment.abuse_score if enriched_alert.enrichment.abuse_score is not None else "N/A"
            
            # Accumulate statistics
            successful += 1
            total_risk += risk_score
            risk_categories[risk_lbl] += 1
            
            details.append({
                "filename": filename,
                "status": "Success",
                "risk_score": risk_score,
                "risk_level": risk_lbl,
                "country": country,
                "abuse_score": abuse_score,
                "latency_ms": latency,
                "error": ""
            })
            
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            failed += 1
            details.append({
                "filename": filename,
                "status": "Failed",
                "risk_score": 0,
                "risk_level": "N/A",
                "country": "N/A",
                "abuse_score": "N/A",
                "latency_ms": latency,
                "error": str(e)
            })

    success_rate = (successful / total) * 100.0 if total > 0 else 0.0
    avg_risk = (total_risk / successful) if successful > 0 else 0.0

    # Write Markdown Report
    report_content = f"""# Sample Alerts Enrichment Report

Generated on: {datetime.now(timezone.utc).isoformat()}

## Summary Statistics

- **Total Alerts Checked**: {total}
- **Enriched Successfully**: {successful}
- **Failed Enrichments**: {failed}
- **Success Rate**: {success_rate:.2f}%
- **Average Risk Score**: {avg_risk:.2f}

## Risk Level Distribution

- **CRITICAL (Score >= 80)**: {risk_categories["CRITICAL"]}
- **HIGH (Score >= 60)**: {risk_categories["HIGH"]}
- **MEDIUM (Score >= 40)**: {risk_categories["MEDIUM"]}
- **LOW (Score < 40)**: {risk_categories["LOW"]}

## Detailed Execution Log

| Filename | Status | Risk Score | Risk Level | Country | AbuseIPDB | Latency (ms) | Error |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
"""

    for item in details:
        report_content += f"| `{item['filename']}` | {item['status']} | {item['risk_score']} | {item['risk_level']} | {item['country']} | {item['abuse_score']} | {item['latency_ms']:.2f} | {item['error']} |\n"

    # Export report to docs/sample_alerts_enrichment_report.md
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(base_dir, "docs", "sample_alerts_enrichment_report.md")
    
    with open(report_path, "w", encoding="utf-8") as rf:
        rf.write(report_content)
        
    print(f"Report generated successfully at: {report_path}")


if __name__ == "__main__":
    main()
