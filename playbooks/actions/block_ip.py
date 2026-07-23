import time
import random
from datetime import datetime
from typing import Any
from . import ActionResult

def block_ip(ip: str, simulate_fail: bool = False) -> ActionResult:
    """
    Mock firewall API call to block an IP address with a realistic 50-200ms delay.
    """
    start_time = time.time()
    
    # Simulate network delay (50-200ms)
    time.sleep(random.uniform(0.05, 0.20))
    
    status = "failed" if (simulate_fail or ip == "error") else "success"
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="block_ip",
        target=ip,
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )

def rate_limit(ip: str, limit: Any = "1000/min", simulate_fail: bool = False) -> ActionResult:
    """
    Mock firewall API call to apply rate limiting to an IP address with a realistic 50-200ms delay.
    """
    start_time = time.time()
    
    # Simulate network delay (50-200ms)
    time.sleep(random.uniform(0.05, 0.20))
    
    status = "failed" if (simulate_fail or ip == "error") else "success"
    duration_ms = int((time.time() - start_time) * 1000)
    
    res = ActionResult(
        action="rate_limit",
        target=ip,
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
    res.limit = limit
    return res

