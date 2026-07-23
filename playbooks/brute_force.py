import time
from typing import Dict, Any, List
from .actions.block_ip import block_ip
from .actions.send_alert import send_notification
from .engine import PlaybookResult

class BruteForcePlaybook:
    """
    Playbook for containing brute force attacks based on risk score.
    """
    MITRE_TECHNIQUE = "T1110"

    def __init__(self):
        self.execution_log: List[Any] = []

    def execute(self, alert: Dict[str, Any], risk_score: float) -> PlaybookResult:
        start_time = time.time()
        actions_taken = []
        ip = alert.get("source_ip") or alert.get("ip") or "10.0.0.10"
        
        if risk_score > 80:
            # score > 80 -> block_ip() + send_notification()
            block_res = block_ip(ip)
            actions_taken.append(block_res)
            
            notif_res = send_notification(
                f"CRITICAL: Brute force attack detected from {ip} (Risk: {risk_score}). IP blocked.",
                "CRITICAL"
            )
            actions_taken.append(notif_res)
            
        elif risk_score >= 50:
            # score 50-80 -> send_notification() only (needs approval)
            notif_res = send_notification(
                f"WARNING: Brute force attempt detected from {ip} (Risk: {risk_score}). Approval required.",
                "WARNING"
            )
            actions_taken.append(notif_res)
            
        else:
            # score < 50 -> log only, no action
            from .actions import ActionResult
            from datetime import datetime
            log_res = ActionResult(
                action="log",
                target=ip,
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

