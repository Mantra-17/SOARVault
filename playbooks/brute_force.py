from typing import List, Dict, Any
from .engine import ActionResult
from .actions import block_ip, send_notification

class BruteForcePlaybook:
    """
    Playbook for mitigating Brute Force attacks.
    MITRE ATT&CK: T1110 (Brute Force)
    """
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.execution_log: List[ActionResult] = []

    def execute(self, alert: Dict[str, Any], risk_score: int) -> List[ActionResult]:
        """Executes playbook logic based on risk score."""
        ip = alert.get("source_ip", "0.0.0.0")
        
        if risk_score > 80:
            self.execution_log.append(block_ip(ip, self.dry_run))
            self.execution_log.append(send_notification(f"Blocked IP {ip}", "CRITICAL", self.dry_run))
        elif 50 <= risk_score <= 80:
            self.execution_log.append(send_notification(f"Brute force from {ip} needs approval", "HIGH", self.dry_run))
        else:
            self.execution_log.append(send_notification(f"Logged brute force from {ip}", "INFO", self.dry_run))
            
        return self.execution_log
