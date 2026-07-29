import time
from datetime import datetime
from . import ActionResult
from playbooks.mock_edr import MockEDR

def isolate_host_edr(host_id: str) -> ActionResult:
    """
    Isolates a host using EDR (CrowdStrike mock API).
    """
    start_time = time.time()
    
    # Use the mock EDR client
    edr = MockEDR()
    result = edr.isolate(host_id)
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="isolate_host_edr",
        target=host_id,
        status=result.get("status", "success"),
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
