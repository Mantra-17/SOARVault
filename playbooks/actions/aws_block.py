import time
import random
from datetime import datetime
from typing import Any
from . import ActionResult

def block_security_group(ip: str, simulate_fail: bool = False) -> ActionResult:
    """
    Mock boto3 Security Group rule add to block an IP with a realistic delay.
    """
    start_time = time.time()
    
    # Simulate API delay (100-300ms)
    time.sleep(random.uniform(0.1, 0.3))
    
    status = "failed" if (simulate_fail or ip == "error") else "success"
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="aws_block",
        target=ip,
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
