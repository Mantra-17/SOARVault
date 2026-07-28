import time
from playbooks.engine import ActionResult
from playbooks.mock_edr import MockEDR

def isolate_host(host_id: str, dry_run: bool = False) -> ActionResult:
    """Isolate a host using the EDR."""
    start = time.time()
    edr = MockEDR()
    
    status = "success"
    if not dry_run:
        status = edr.isolate(host_id)
        
    end = time.time()
    
    return ActionResult(
        action="isolate_host",
        target=host_id,
        status=status if not dry_run else "dry_run_success",
        duration_ms=int((end - start) * 1000),
        reversible=True
    )
