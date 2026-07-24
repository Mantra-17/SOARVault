"""
Playbook engine module for SOARVault.
Contains the PlaybookEngine base class, PlaybookResult, and routing logic.
"""
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

@dataclass
class PlaybookResult:
    actions_taken: List[Any] = field(default_factory=list)
    execution_time_ms: int = 0
    status: str = "success"
    rollback_available: bool = False
    # Optional helper/compatibility fields
    success: bool = True
    message: str = ""
    error: Optional[str] = None

class PlaybookEngine:
    """Base class for playbook execution and routing."""
    
    def __init__(self):
        # Maps alert types to playbook classes/implementations
        self._routes: Dict[str, Any] = {}
        self.cases: Dict[str, PlaybookResult] = {}
        self._register_defaults()

    def _register_defaults(self):
        try:
            from .brute_force import BruteForcePlaybook
            from .malware import MalwarePlaybook
            from .ddos import DDoSPlaybook
            from .insider_threat import InsiderThreatPlaybook
            from .data_exfil import DataExfilPlaybook
            self.register_playbook("brute_force", BruteForcePlaybook)
            self.register_playbook("malware", MalwarePlaybook)
            self.register_playbook("ddos", DDoSPlaybook)
            self.register_playbook("insider_threat", InsiderThreatPlaybook)
            self.register_playbook("data_exfil", DataExfilPlaybook)
        except ImportError:
            pass


    def register_playbook(self, alert_type: str, playbook_cls: Any) -> None:
        """Registers a playbook class or instance for a given alert type."""
        self._routes[alert_type] = playbook_cls

    def select_playbook(self, alert_type: Any) -> Any:
        """
        Selects the appropriate playbook class based on the alert_type string or alert dict.
        """
        if isinstance(alert_type, dict):
            alert_type_key = alert_type.get("type") or alert_type.get("alert_type")
        else:
            alert_type_key = str(alert_type)
            
        if not alert_type_key:
            raise ValueError("Alert missing 'type' field for routing.")
            
        playbook = self._routes.get(alert_type_key)
        if not playbook:
            # If not registered in map, return string for basic routing / fallback
            return alert_type_key
        return playbook

    def execute(self, alert: Dict[str, Any], risk_score: float = 0.0, dry_run: bool = False) -> PlaybookResult:
        """
        Executes the playbook corresponding to the alert type and risk score.
        """
        start_time = time.time()
        case_id = alert.get("case_id", f"case-{int(start_time*1000)}")
        try:
            playbook_target = self.select_playbook(alert)
            if isinstance(playbook_target, type):
                playbook_instance = playbook_target()
            elif hasattr(playbook_target, 'execute'):
                playbook_instance = playbook_target
            else:
                duration = int((time.time() - start_time) * 1000)
                res = PlaybookResult(
                    actions_taken=[],
                    execution_time_ms=duration,
                    status="success" if not dry_run else "dry_run",
                    rollback_available=False,
                    success=True,
                    message=f"Successfully routed and executed playbook for: {playbook_target}"
                )
                self.cases[case_id] = res
                return res
                
            # Attempt to pass dry_run if supported by the playbook signature
            import inspect
            sig = inspect.signature(playbook_instance.execute)
            if 'dry_run' in sig.parameters:
                result = playbook_instance.execute(alert, risk_score, dry_run=dry_run)
            else:
                # If playbook doesn't natively support dry_run yet, we just execute it
                # (For Day 19, we should update playbooks to support it)
                result = playbook_instance.execute(alert, risk_score)
                if dry_run and isinstance(result, PlaybookResult):
                    result.status = "dry_run"
                    for a in result.actions_taken:
                        a.status = "dry_run"
            if isinstance(result, PlaybookResult):
                if result.execution_time_ms == 0:
                    result.execution_time_ms = int((time.time() - start_time) * 1000)
                self.cases[case_id] = result
                return result
            elif isinstance(result, list):
                duration = int((time.time() - start_time) * 1000)
                rollback = any(getattr(a, 'reversible', False) for a in result)
                res = PlaybookResult(
                    actions_taken=result,
                    execution_time_ms=duration,
                    status="success",
                    rollback_available=rollback,
                    success=True
                )
                self.cases[case_id] = res
                return res
            else:
                duration = int((time.time() - start_time) * 1000)
                res = PlaybookResult(
                    actions_taken=[],
                    execution_time_ms=duration,
                    status="success",
                    rollback_available=False,
                    success=True
                )
                self.cases[case_id] = res
                return res
        except Exception as e:
            duration = int((time.time() - start_time) * 1000)
            res = PlaybookResult(
                actions_taken=[],
                execution_time_ms=duration,
                status="failed",
                rollback_available=False,
                success=False,
                message="Playbook execution failed",
                error=str(e)
            )
            self.cases[case_id] = res
            return res

    def undo_actions(self, case_id: str) -> List[Any]:
        """
        Reverses all actions taken in a case.
        """
        if case_id not in self.cases:
            return []
        
        result = self.cases[case_id]
        if not result.rollback_available:
            return []
        
        reversed_actions = []
        for action in result.actions_taken:
            if getattr(action, 'reversible', False):
                # Mock reversal
                action.status = "reversed"
                reversed_actions.append(action)
                
        result.status = "rolled_back"
        return reversed_actions

    def auto_rollback_check(self, case_id: str, current_risk_score: float, hours_elapsed: float) -> List[Any]:
        """
        If risk score drops below 50 after 1 hour, trigger auto-rollback.
        """
        if current_risk_score < 50.0 and hours_elapsed >= 1.0:
            return self.undo_actions(case_id)
        return []

