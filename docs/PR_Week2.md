# Pull Request: Week 2 - Playbook Engine & Core Responses

## Description
This PR implements the core execution engine and all 5 primary security playbooks for SOARVault, along with their respective mock containment actions. It also introduces our automated rollback system.

## Playbooks Implemented
1. **Brute Force** (`brute_force.py`) - IP blocking and notifications.
2. **Malware** (`malware.py`) - EDR host isolation and critical response.
3. **DDoS** (`ddos.py`) - IP rate limiting and mitigation.
4. **Data Exfiltration** (`data_exfil.py`) - Outbound traffic blocking and host isolation.
5. **Insider Threat** (`insider_threat.py`) - Active Directory account disabling.

## Rollback System
- **Manual Rollback**: Added `undo_actions(case_id)` to `PlaybookEngine`. Any action that returns an `ActionResult` with `reversible=True` (e.g., `block_ip`, `isolate_host`, `aws_block`) can be reversed.
- **Auto-Rollback**: Added `auto_rollback_check(case_id, current_risk_score, hours_elapsed)`. If a risk score drops below 50 after 1 hour, temporary containment actions are automatically undone to restore access for false positives.

## Actions Added
- `block_ip` / `rate_limit`
- `isolate_host`
- `send_alert`
- `block_outbound`
- `disable_account`
- `aws_block` (AWS Security Group rule mock)

## Next Steps
- Finalize MITRE ATT&CK mapping (Week 3)
- Write full end-to-end unit tests
