import time
from playbooks.engine import ActionResult

def block_outbound(host_id: str, dry_run: bool = False) -> ActionResult:
    """Mock firewall outbound rule addition."""
    start = time.time()
    if not dry_run:
        time.sleep(0.1)
    end = time.time()
    
    return ActionResult(
        action="block_outbound",
        target=host_id,
        status="success" if not dry_run else "dry_run_success",
        duration_ms=int((end - start) * 1000),
        reversible=True
    )
