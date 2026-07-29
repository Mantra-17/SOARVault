import time
from typing import Dict, Any, List, Optional
from datetime import datetime

class ActionResult:
    """Represents the result of a single action in a playbook."""
    def __init__(self, action: str, target: str, status: str, duration_ms: int, reversible: bool = False):
        self.action = action
        self.target = target
        self.status = status
        self.timestamp = datetime.utcnow().isoformat()
        self.duration_ms = duration_ms
        self.reversible = reversible

class PlaybookResult:
    """Represents the complete result of executing a playbook."""
    def __init__(self, status: str, execution_time_ms: int, actions_taken: List[ActionResult], rollback_available: bool = False):
        self.status = status
        self.execution_time_ms = execution_time_ms
        self.actions_taken = actions_taken
        self.rollback_available = rollback_available

class PlaybookEngine:
    """
    Base orchestrator for executing security playbooks.
    """
    def __init__(self):
        self.case_history = {}  # case_id -> PlaybookResult

    def select_playbook(self, alert_type: str):
        """Returns the appropriate playbook class for a given alert type."""
        from .brute_force import BruteForcePlaybook
        from .malware import MalwarePlaybook
        from .ddos import DDoSPlaybook
        from .data_exfil import DataExfilPlaybook
        from .insider_threat import InsiderThreatPlaybook
        
        mapping = {
            "brute_force": BruteForcePlaybook,
            "malware": MalwarePlaybook,
            "ddos": DDoSPlaybook,
            "data_exfil": DataExfilPlaybook,
            "insider_threat": InsiderThreatPlaybook
        }
        return mapping.get(alert_type.lower())

    def execute(self, alert: Dict[str, Any], risk_score: int, case_id: str, dry_run: bool = False) -> PlaybookResult:
        """
        Execute the appropriate playbook based on alert type and risk score.
        """
        start_time = time.time()
        alert_type = alert.get("type", "unknown")
        
        playbook_cls = self.select_playbook(alert_type)
        if not playbook_cls:
            return PlaybookResult(status="failed - unknown alert type", execution_time_ms=0, actions_taken=[])
            
        playbook = playbook_cls(dry_run=dry_run)
        actions = playbook.execute(alert, risk_score)
        
        end_time = time.time()
        execution_time_ms = int((end_time - start_time) * 1000)
        
        rollback_available = any(a.reversible for a in actions)
        
        result = PlaybookResult(
            status="success",
            execution_time_ms=execution_time_ms,
            actions_taken=actions,
            rollback_available=rollback_available
        )
        self.case_history[case_id] = result
        return result

    def undo_actions(self, case_id: str) -> bool:
        """
        Rollback actions for a specific case if they are reversible.
        """
        if case_id not in self.case_history:
            return False
            
        result = self.case_history[case_id]
        if not result.rollback_available:
            return False
            
        # Mock reverse actions
        for action in reversed(result.actions_taken):
            if action.reversible:
                action.status = "rolled_back"
                
        result.rollback_available = False
        return True

    def check_auto_rollback(self, case_id: str, current_risk_score: int, hours_elapsed: float):
        """
        Automatically trigger rollback if risk score drops below 50 after 1 hour.
        """
        if current_risk_score < 50 and hours_elapsed >= 1.0:
            return self.undo_actions(case_id)
        return False
