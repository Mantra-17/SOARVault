import time
import random
from datetime import datetime
from . import ActionResult

def block_outbound_traffic(target: str) -> ActionResult:
    """
    Mock block outbound traffic for an IP or subnet.
    """
    start_time = time.time()
    time.sleep(random.uniform(0.1, 0.25))
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="block_outbound_traffic",
        target=target,
        status="success",
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
