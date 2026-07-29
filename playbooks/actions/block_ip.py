import time
import random
from datetime import datetime
from . import ActionResult

def block_ip_edge_firewall(ip: str) -> ActionResult:
    """
    Mock block IP on Perimeter Firewall (Palo Alto).
    """
    start_time = time.time()
    
    # Simulate firewall policy update time
    time.sleep(random.uniform(0.1, 0.3))
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ActionResult(
        action="block_ip_edge_firewall",
        target=ip,
        status="success",
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True
    )
