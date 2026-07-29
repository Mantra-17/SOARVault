import time
from playbooks.engine import ActionResult

def block_ip(ip: str, dry_run: bool = False) -> ActionResult:
    """Mock firewall API call to block an IP."""
    start = time.time()
    if not dry_run:
        time.sleep(0.1) # 100ms realistic delay
    end = time.time()
    
    return ActionResult(
        action="block_ip",
        target=ip,
        status="success" if not dry_run else "dry_run_success",
        duration_ms=int((end - start) * 1000),
        reversible=True
    )

def rate_limit(ip: str, limit: int, dry_run: bool = False) -> ActionResult:
    """Mock rate limit action for DDoS mitigation."""
    start = time.time()
    if not dry_run:
        time.sleep(0.05)
    end = time.time()
    
    return ActionResult(
        action="rate_limit",
        target=ip,
        status=f"limited_to_{limit}" if not dry_run else "dry_run_success",
        duration_ms=int((end - start) * 1000),
        reversible=True
    )
