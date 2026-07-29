# SOARVault Data Normalization Schema

The Normalizer (`ingestion/normalizer.py`) is responsible for translating disparate SIEM payloads (Splunk, QRadar, CrowdStrike, raw JSON) into our canonical `NormalizedAlert` Pydantic model.

## Core Mapping Rules

### 1. Timestamps (`normalize_timestamp`)
SIEMs send timestamps in various formats (ISO-8601, Unix Epoch, localized strings).
* **Rule:** All timestamps are parsed and converted to **UTC-aware `datetime` objects** at the boundary.
* **Fields:** `detected_at` and `ingested_at`.
* **Validation:** Checked automatically by the `parse_detected_at` Pydantic pre-validator.

### 2. Network Context (`extract_source_ip`, `extract_destination_ip`)
Network metadata is mapped into the `NetworkContext` sub-model.
* **Source IP:** Extracted from keys like `src_ip`, `source_address`, `client_ip`.
* **Destination IP:** Extracted from `dst_ip`, `destination_address`, `server_ip`.
* **Validation:** Both IPv4 and IPv6 strings are checked against strict regex patterns.

### 3. Severity Mapping
SIEMs send severity as ints (0-10) or custom strings (e.g., `high`, `critical`, `Sev1`).
* **Rule:** Mapped to the `Severity` Enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
* Example: `10` -> `CRITICAL`, `Sev1` -> `CRITICAL`.

### 4. Alert Categorization
Mapping the incoming detection rule to our `AlertType` Enum.
* Brute Force -> `AlertType.BRUTE_FORCE`
* Malware / EDR -> `AlertType.MALWARE`
* Phishing / Email -> `AlertType.PHISHING`
* Default / Fallback -> `AlertType.UNKNOWN`

### 5. IoC Extraction
Indicators of Compromise (IoCs) are parsed into the `IoC` model list (`alert.iocs`).
* **Types:** `ip`, `domain`, `file_hash`, `url`, `email`.
* **Rule:** File hashes (MD5, SHA1, SHA256) are always normalized to lower-case hexadecimal strings before storage to ensure consistent VT lookups.
