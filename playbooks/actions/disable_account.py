import time
import random
from datetime import datetime
from . import ActionResult

def disable_account(username: str, simulate_fail: bool = False) -> ActionResult:
    """
    Mock AD account disable action.
    """
    start_time = time.time()
    
    # Simulate API/AD delay (100-300ms)
    time.sleep(random.uniform(0.1, 0.3))
    
    status = "failed" if simulate_fail else "success"
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="disable_account",
        target=username,
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
