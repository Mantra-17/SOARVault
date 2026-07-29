# SOARVault Enrichment Module: Technical Viva and Presentation Prep

This document serves as a study guide and presentation template for the Threat Intelligence Enrichment Module viva.

---

## 1. Core Threat Intelligence Integrations

### AbuseIPDB
- **Purpose**: Provides IP address reputation data, detecting whether an IP is associated with spamming, hacking, scanning, or DDoS activity.
- **Data Returned**: Abuse Confidence Score (0-100), total reports count, country code, ISP name, and timestamp of the last report.
- **Design Decision**: API calls are made using `httpx.get()` (sync) and `httpx.AsyncClient` (async) with local JSON fallback mocks for offline development and fast testing cycles.

### VirusTotal
- **Purpose**: Verifies domain names and file hashes against 70+ antivirus engines.
- **Data Returned**: Number of malicious/harmless/suspicious votes and a simplified verdict (`MALICIOUS` or `CLEAN`).
- **Design Decision**: Submits requests asynchronously via the VirusTotal v3 HTTP API. Extends support to match MD5, SHA-1, and SHA-256 hashes.

### GeoIP (ip-api.com)
- **Purpose**: Resolves physical geolocation (Country, City, Region, Latitude/Longitude) and Autonomous System Number (ASN) details.
- **Design Decision**: Uses `ip-api.com` without authentication requirements. Implemented offline guards to avoid timeouts during pipeline execution.

---

## 2. Risk Scoring & Country Weighting

### Composite Score Formula
$$RiskScore = (AbuseScore \times 0.5) + (VTRatio \times 100 \times 0.3) + (CountryRisk \times 0.2)$$
- **AbuseIPDB Weight (50%)**: Direct indicator of active abuse behavior.
- **VirusTotal Weight (30%)**: Indicator of association with malware binaries or malicious domains.
- **Country Risk Weight (20%)**: Multiplier based on geolocated threat origin.
- **Attacker Persistence Bonus (+20)**: Added if the IP is recorded as a repeat attacker.
- **Score Clamping**: Strictly capped at `100` via Python's `min(100, score)`.

### Configurable Country Weighting
- Country codes are parsed dynamically from environment variables:
  - `SOARVAULT_HIGHEST_RISK_COUNTRIES` (defaults to `KP` -> score 100)
  - `SOARVAULT_HIGH_RISK_COUNTRIES` (defaults to `RU,CN,BY` -> score 75)
  - `SOARVAULT_MEDIUM_RISK_COUNTRIES` (defaults to `IR,SY,VE,CU,MM` -> score 50)
- Overriding weight sets does not require redeploying code.

---

## 3. Performance & Cache Optimization

### Redis Caching
- **Implementation**: Checks the cache keyspace (`cache:ioc:{ioc_value}`) before initiating slow HTTP requests.
- **TTL**: 3600 seconds (1 hour) to keep reputation data fresh.
- **Performance impact**: Latency drops from **~350 ms** (network request) to **<1 ms** (Redis read).
- **Telemetry stats**: Increments Redis metrics (`stats:cache_hits`, `stats:cache_misses`) to compute hit/miss efficiency ratios.

### Concurrent Batch Enrichment
- **Asynchronous Execution**: Uses `asyncio.gather` inside `batch_enricher.py`.
- **Latency reduction**: Queries multiple indicators in parallel instead of sequentially.
- **Retry with Exponential Backoff**: Retries failed lookups with backoff delay to handle network blips.
- **Resilience**: If a lookup for a single IP in a batch fails, the engine aggregates its error and continues processing other items without stopping.

---

## 4. Security Logic & Framework Mapping

### False-Positive Detection
- Flags benign IPs (like Google Public DNS, Cloudflare resolver, or trusted cloud hosts) as `Potential False Positive`.
- Explains why the indicator is likely benign (e.g., zero VT malicious detections and reputable ISP context).
- Prevents alert fatigue in the SOC.

### MITRE ATT&CK Mapping
- Automatically links normalized alerts (like `ssh_brute_force` or `ransomware_activity`) to MITRE ATT&CK Technique IDs (e.g., `T1110.001` or `T1486`) and Tactics (e.g., `Credential Access`, `Impact`).
- Built as an extensible database mapping that parses alert details for fuzzy matches.
