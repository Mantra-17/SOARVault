import time
from typing import Dict, Any, List
from .actions.isolate_host import isolate_host
from .actions.block_outbound import block_outbound
from .actions.send_alert import send_notification
from .engine import PlaybookResult

class DataExfilPlaybook:
    """
    Playbook for mitigating data exfiltration by isolating hosts and blocking outbound traffic.
    Data exfil is always treated as CRITICAL severity.
    """
    def __init__(self):
        self.execution_log: List[Any] = []

    def execute(self, alert: Dict[str, Any], risk_score: float) -> PlaybookResult:
        start_time = time.time()
        actions_taken = []
        
        host_id = alert.get("host_id", "unknown_host")
        dest_ip = alert.get("dest_ip", "unknown_ip")
        
        # Data exfil is treated as CRITICAL. 
        # >75 gets isolation + block outbound + CISO notification
        if risk_score > 75:
            iso_res = isolate_host(host_id)
            actions_taken.append(iso_res)
            
            block_res = block_outbound(host_id, dest_ip)
            actions_taken.append(block_res)
            
            ciso_notif = send_notification(
                f"CRITICAL: Data Exfiltration detected on {host_id} to {dest_ip} (Risk: {risk_score}). Host isolated and outbound traffic blocked. Escalated to CISO.",
                "CRITICAL"
            )
            actions_taken.append(ciso_notif)
            
        elif risk_score >= 50:
            notif_res = send_notification(
                f"CRITICAL: Potential Data Exfiltration on {host_id} (Risk: {risk_score}). Activity logged and flagged for review.",
                "CRITICAL"
            )
            actions_taken.append(notif_res)
            
        else:
            from .actions import ActionResult
            from datetime import datetime
            log_res = ActionResult(
                action="log",
                target=host_id,
                status="logged (CRITICAL severity)",
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
