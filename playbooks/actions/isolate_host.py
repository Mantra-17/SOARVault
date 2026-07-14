import time
import random
from datetime import datetime
from . import ActionResult

def isolate_host(host_id: str) -> ActionResult:
    """
    Mock EDR/Network action to isolate a host with a realistic 50-200ms delay.
    """
    start_time = time.time()
    
    # Simulate network/EDR delay (50-200ms)
    time.sleep(random.uniform(0.05, 0.20))
    
    status = "success" if random.random() > 0.05 else "failed"
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="isolate_host",
        target=host_id,
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
