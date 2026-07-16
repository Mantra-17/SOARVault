import time
import random
from datetime import datetime
from . import ActionResult

def isolate_host(host_id: str, simulate_fail: bool = False) -> ActionResult:
    """
    Mock EDR/Network action to isolate a host with a realistic 50-200ms delay.
    """
    start_time = time.time()
    
    # Simulate network/EDR delay (50-200ms)
    time.sleep(random.uniform(0.05, 0.20))
    
    status = "failed" if (simulate_fail or host_id == "error") else "success"
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="isolate_host",
        target=host_id,
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )

