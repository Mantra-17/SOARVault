# Playbooks Module

This module orchestrates automated responses to security alerts using predefined playbooks.

## Playbooks

### Brute Force (T1110)
- **Risk > 80**: Block IP, Notify
- **Risk 50-80**: Notify (Needs Approval)
- **Risk < 50**: Log

### Malware (T1204)
- **Risk > 80**: Isolate Host, Block IP, Notify
- **Risk 50-80**: Notify (Needs Approval)

### DDoS (T1498)
- **Risk > 70**: Block IP, Rate Limit, Notify

### Data Exfiltration (T1041)
- **Risk > 75**: Isolate Host, Block Outbound, Notify

### Insider Threat (T1078)
- **Off-hours + Unusual**: Disable Account, Notify HR & CISO
- **Risk > 80**: Disable Account, Notify CISO

## Rollback
Supports rollback of reversible actions (like IP blocks and host isolation). Auto-rollback is triggered if the risk drops below 50 after 1 hour.

## Dry-Run
Playbooks can be executed with `dry_run=True` to simulate execution without taking actual actions.
