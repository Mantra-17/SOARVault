from typing import List, Dict, Any
from .engine import ActionResult
from .actions import disable_account, send_notification

class InsiderThreatPlaybook:
    """
    Playbook for detecting and responding to Insider Threats.
    MITRE ATT&CK: T1078 (Valid Accounts)
    """
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.execution_log: List[ActionResult] = []

    def execute(self, alert: Dict[str, Any], risk_score: int) -> List[ActionResult]:
        """Executes insider threat detection logic."""
        user_id = alert.get("user_id", "unknown")
        hour = alert.get("hour_of_day", 12)
        unusual_access = alert.get("unusual_access", False)
        
        # Off-hours access (10pm-6am) + unusual resource access = HIGH risk
        is_off_hours = hour >= 22 or hour <= 6
        
        if is_off_hours and unusual_access:
            self.execution_log.append(disable_account(user_id, self.dry_run))
            self.execution_log.append(send_notification(f"HR & CISO: Insider threat suspected, disabled {user_id}", "CRITICAL", self.dry_run))
        elif risk_score > 80:
            self.execution_log.append(disable_account(user_id, self.dry_run))
            self.execution_log.append(send_notification(f"CISO: Disabled high risk account {user_id}", "HIGH", self.dry_run))
            
        return self.execution_log
