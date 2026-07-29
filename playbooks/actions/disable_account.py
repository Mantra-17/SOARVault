import time
from playbooks.engine import ActionResult

def disable_account(user_id: str, dry_run: bool = False) -> ActionResult:
    """Mock AD account disable action."""
    start = time.time()
    if not dry_run:
        time.sleep(0.15)
    end = time.time()
    
    return ActionResult(
        action="disable_account",
        target=user_id,
        status="success" if not dry_run else "dry_run_success",
        duration_ms=int((end - start) * 1000),
        reversible=True
    )
