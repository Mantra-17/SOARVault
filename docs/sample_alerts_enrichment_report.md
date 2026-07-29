# Sample Alerts Enrichment Report

Generated on: 2026-07-29T14:56:31.608315+00:00

## Summary Statistics

- **Total Alerts Checked**: 17
- **Enriched Successfully**: 17
- **Failed Enrichments**: 0
- **Success Rate**: 100.00%
- **Average Risk Score**: 34.06

## Risk Level Distribution

- **CRITICAL (Score >= 80)**: 0
- **HIGH (Score >= 60)**: 0
- **MEDIUM (Score >= 40)**: 6
- **LOW (Score < 40)**: 11

## Detailed Execution Log

| Filename | Status | Risk Score | Risk Level | Country | AbuseIPDB | Latency (ms) | Error |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `brute_force.json` | Success | 38.0 | LOW | US | 75 | 5390.14 |  |
| `c2_beaconing.json` | Success | 45.0 | MEDIUM | US | 90 | 3.60 |  |
| `crowdstrike_exfil.json` | Success | 38.0 | LOW | US | 75 | 2.29 |  |
| `cryptominer_execution.json` | Success | 38.0 | LOW | US | 75 | 3.54 |  |
| `data_exfil_ecs.json` | Success | 50.0 | MEDIUM | US | 100 | 2.58 |  |
| `ddos_reflection.json` | Success | 15.0 | LOW | US | 30 | 2.27 |  |
| `insider_threat_syslog.json` | Success | 28.0 | LOW | N/A | N/A | 1.13 |  |
| `ipv6_ddos.json` | Success | 0.0 | LOW | US | 0 | 2.89 |  |
| `malformed_timestamp.json` | Success | 8.0 | LOW | US | 15 | 1.84 |  |
| `malware_lockbit.json` | Success | 56.0 | MEDIUM | US | 90 | 5.75 |  |
| `phishing_credential_harvest.json` | Success | 38.0 | LOW | US | 75 | 2.67 |  |
| `phishing_o365.json` | Success | 17.0 | LOW | N/A | N/A | 2.30 |  |
| `qradar_malware.json` | Success | 28.0 | LOW | N/A | N/A | 1.42 |  |
| `ransomware_activity.json` | Success | 50.0 | MEDIUM | US | 100 | 4.44 |  |
| `rdp_brute_force_external.json` | Success | 38.0 | LOW | US | 75 | 3.86 |  |
| `splunk_bruteforce.json` | Success | 50.0 | MEDIUM | US | 100 | 2.82 |  |
| `tor_exit_node_activity.json` | Success | 42.0 | MEDIUM | US | 85 | 2.62 |  |
