# Playbooks Documentation

## Playbook Rollback System

SOARVault supports an automated playbook rollback mechanism to reverse containment actions when risk levels decrease or false positives are identified. 

### How it Works
- Each execution is tracked with a `case_id` inside the `PlaybookEngine`.
- Executed actions that are marked as `reversible=True` (e.g., `block_ip`, `isolate_host`, `aws_block`) can be undone via the `undo_actions(case_id)` method.
- **Auto-Rollback**: The engine supports `auto_rollback_check(case_id, current_risk_score, hours_elapsed)`. If the risk score drops below 50 after 1 hour, auto-rollback is triggered automatically reversing all temporary containment actions.
