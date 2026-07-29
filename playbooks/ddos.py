from typing import List, Dict, Any
from .engine import ActionResult
from .actions import block_ip, rate_limit, send_notification

class DDoSPlaybook:
    """
    Playbook for DDoS mitigation.
    MITRE ATT&CK: T1498 (Network Denial of Service)
    """
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.execution_log: List[ActionResult] = []

    def execute(self, alert: Dict[str, Any], risk_score: int) -> List[ActionResult]:
        """Executes DDoS mitigation logic."""
        ip = alert.get("source_ip", "0.0.0.0")
        
        if risk_score > 70:
            self.execution_log.append(block_ip(ip, self.dry_run))
            self.execution_log.append(rate_limit(ip, 100, self.dry_run))
            self.execution_log.append(send_notification(f"DDoS mitigation applied to {ip}", "CRITICAL", self.dry_run))
            
        return self.execution_log
