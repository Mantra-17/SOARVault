import time
import random
from datetime import datetime
from . import ActionResult

def send_notification(message: str, severity: str) -> ActionResult:
    """
    Mock Slack webhook call with a realistic response delay.
    """
    start_time = time.time()
    
    # Simulate network delay (50-150ms)
    time.sleep(random.uniform(0.05, 0.15))
    
    status = "success" if random.random() > 0.05 else "failed"
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="send_notification",
        target="slack_webhook",
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=False
    )
