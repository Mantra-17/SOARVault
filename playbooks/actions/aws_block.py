import time
import random
from datetime import datetime
from . import ActionResult

def add_security_group_rule(ip: str, port: int = 443, protocol: str = "tcp", simulate_fail: bool = False) -> ActionResult:
    """
    Mock boto3 Security Group rule add to block or allow traffic.
    """
    start_time = time.time()
    
    # Simulate network/AWS delay
    time.sleep(random.uniform(0.1, 0.3))
    
    status = "failed" if (simulate_fail or ip == "error") else "success"
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="aws_block",
        target=f"{ip}:{port}/{protocol}",
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
