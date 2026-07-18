import time
from typing import Dict, Any, List
from .actions.disable_account import disable_account
from .actions.send_alert import send_notification
from .engine import PlaybookResult

class InsiderThreatPlaybook:
    """
    Playbook for detecting and responding to insider threats based on risk score
    and context (off-hours access, unusual resources).
    """
    def __init__(self):
        self.execution_log: List[Any] = []

    def execute(self, alert: Dict[str, Any], risk_score: float) -> PlaybookResult:
        start_time = time.time()
        actions_taken = []
        
        username = alert.get("username") or alert.get("user") or "unknown_user"
        off_hours = alert.get("off_hours", False)
        unusual_resource = alert.get("unusual_resource", False)
        
        # High risk if off_hours (10pm-6am) and unusual_resource
        is_high_risk = off_hours and unusual_resource
        
        if is_high_risk or risk_score > 75:
            # disable_account() (mock) + notify HR + notify CISO
            disable_res = disable_account(username)
            actions_taken.append(disable_res)
            
            hr_notif = send_notification(
                f"CRITICAL: Insider Threat detected for {username} (Risk: {risk_score}). Account disabled. Please review.",
                "CRITICAL"
            )
            actions_taken.append(hr_notif)
            
            ciso_notif = send_notification(
                f"CRITICAL: Insider Threat detected for {username}. Account disabled. Escalated to CISO.",
                "CRITICAL"
            )
            actions_taken.append(ciso_notif)
            
        elif risk_score >= 50:
            notif_res = send_notification(
                f"WARNING: Potential Insider Threat for {username} (Risk: {risk_score}). Activity logged and flagged for review.",
                "WARNING"
            )
            actions_taken.append(notif_res)
            
        else:
            from .actions import ActionResult
            from datetime import datetime
            log_res = ActionResult(
                action="log",
                target=username,
                status="logged",
                timestamp=datetime.utcnow().isoformat(),
                duration_ms=0,
                reversible=False
            )
            actions_taken.append(log_res)

        self.execution_log.extend(actions_taken)
        
        duration_ms = int((time.time() - start_time) * 1000)
        total_action_time = sum(getattr(a, 'duration_ms', 0) for a in actions_taken)
        exec_time = max(duration_ms, total_action_time)
        
        rollback_avail = any(getattr(a, 'reversible', False) for a in actions_taken)
        
        return PlaybookResult(
            actions_taken=actions_taken,
            execution_time_ms=exec_time,
            status="success",
            rollback_available=rollback_avail
        )
