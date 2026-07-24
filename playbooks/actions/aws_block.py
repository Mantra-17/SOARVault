import time
import random
from datetime import datetime
from . import ActionResult

def quarantine_security_group(instance_id: str) -> ActionResult:
    """
    Mock AWS EC2 isolation. Changes the instance's security group to a quarantine group.
    """
    start_time = time.time()
    
    # Simulate AWS API delay
    time.sleep(random.uniform(0.2, 0.4))
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="quarantine_security_group",
        target=instance_id,
        status="success",
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
