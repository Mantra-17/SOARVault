import time
from datetime import datetime
from playbooks.actions import ActionResult  # ActionResult is defined here, not in engine


def send_notification(message: str, severity: str = "medium", dry_run: bool = False) -> ActionResult:
    """Mock Slack webhook call for sending notifications."""
    start = time.time()
    if not dry_run:
        time.sleep(0.02)
    end = time.time()

    return ActionResult(
        action="send_notification",
        target=severity,
        status="success" if not dry_run else "dry_run_success",
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=int((end - start) * 1000),
        reversible=False,
    )


def notify_slack(target_id: str) -> ActionResult:
    """Alias/handler for notify_slack playbook action."""
    return send_notification(
        message=f"Alert notification sent for: {target_id}",
        severity="medium",
    )
