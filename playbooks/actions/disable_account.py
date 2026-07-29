import time
import random
from datetime import datetime
from . import ActionResult

def disable_user_account(username: str) -> ActionResult:
    """
    Mock Active Directory or Identity Provider account disablement.
    """
    start_time = time.time()
    time.sleep(random.uniform(0.15, 0.35))
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="disable_user_account",
        target=username,
        status="success",
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
