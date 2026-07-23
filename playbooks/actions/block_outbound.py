import time
from datetime import datetime
from . import ActionResult

def block_outbound(host_id: str, dest_ip: str) -> ActionResult:
    """Mock firewall outbound rule creation with realistic delay."""
    start_time = time.time()
    time.sleep(0.05)  # 50ms delay
    
    return ActionResult(
        action="block_outbound",
        target=f"{host_id}->{dest_ip}",
        status="success",
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=int((time.time() - start_time) * 1000),
        reversible=True
    )
