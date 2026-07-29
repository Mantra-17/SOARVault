import time
from playbooks.engine import ActionResult

def add_security_group_rule(ip: str, group_id: str, dry_run: bool = False) -> ActionResult:
    """Mock boto3 Security Group rule addition."""
    start = time.time()
    if not dry_run:
        time.sleep(0.2)
    end = time.time()
    
    return ActionResult(
        action="aws_sg_block",
        target=f"{group_id}:{ip}",
        status="success" if not dry_run else "dry_run_success",
        duration_ms=int((end - start) * 1000),
        reversible=True
    )
