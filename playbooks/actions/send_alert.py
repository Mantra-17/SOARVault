import time
from playbooks.engine import ActionResult

def send_notification(message: str, severity: str, dry_run: bool = False) -> ActionResult:
    """Mock Slack webhook call for sending notifications."""
    start = time.time()
    if not dry_run:
        time.sleep(0.02)
    end = time.time()
    
    return ActionResult(
        action="send_notification",
        target=severity,
        status="success" if not dry_run else "dry_run_success",
        duration_ms=int((end - start) * 1000),
        reversible=False
    )

def notify_slack(target_id: str) -> ActionResult:
    """
    Alias/handler for notify_slack playbook action.
    """
    return send_notification(f"Alert notification sent for: {target_id}", "medium")
