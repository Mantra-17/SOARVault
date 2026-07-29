from typing import List, Dict, Any
from .engine import ActionResult
from .actions import isolate_host, block_outbound, send_notification

class DataExfilPlaybook:
    """
    Playbook for preventing Data Exfiltration.
    MITRE ATT&CK: T1041 (Exfiltration Over C2 Channel)
    """
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.execution_log: List[ActionResult] = []

    def execute(self, alert: Dict[str, Any], risk_score: int) -> List[ActionResult]:
        """Executes data exfiltration prevention logic."""
        host_id = alert.get("host_id", "unknown")
        
        # Always treated as CRITICAL for data exfiltration if score > 75
        if risk_score > 75:
            self.execution_log.append(isolate_host(host_id, self.dry_run))
            self.execution_log.append(block_outbound(host_id, self.dry_run))
            self.execution_log.append(send_notification(f"Data exfiltration prevented on {host_id}", "CRITICAL", self.dry_run))
            
        return self.execution_log
