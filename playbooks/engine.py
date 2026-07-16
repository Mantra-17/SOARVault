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
        self._register_defaults()

    def _register_defaults(self):
        try:
            from .brute_force import BruteForcePlaybook
            from .malware import MalwarePlaybook
            self.register_playbook("brute_force", BruteForcePlaybook)
            self.register_playbook("malware", MalwarePlaybook)
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

    def execute(self, alert: Dict[str, Any], risk_score: float = 0.0) -> PlaybookResult:
        """
        Executes the playbook corresponding to the alert type and risk score.
        """
        start_time = time.time()
        try:
            playbook_target = self.select_playbook(alert)
            if isinstance(playbook_target, type):
                playbook_instance = playbook_target()
            elif hasattr(playbook_target, 'execute'):
                playbook_instance = playbook_target
            else:
                duration = int((time.time() - start_time) * 1000)
                return PlaybookResult(
                    actions_taken=[],
                    execution_time_ms=duration,
                    status="success",
                    rollback_available=False,
                    success=True,
                    message=f"Successfully routed and executed playbook for: {playbook_target}"
                )
                
            result = playbook_instance.execute(alert, risk_score)
            if isinstance(result, PlaybookResult):
                if result.execution_time_ms == 0:
                    result.execution_time_ms = int((time.time() - start_time) * 1000)
                return result
            elif isinstance(result, list):
                duration = int((time.time() - start_time) * 1000)
                rollback = any(getattr(a, 'reversible', False) for a in result)
                return PlaybookResult(
                    actions_taken=result,
                    execution_time_ms=duration,
                    status="success",
                    rollback_available=rollback,
                    success=True
                )
            else:
                duration = int((time.time() - start_time) * 1000)
                return PlaybookResult(
                    actions_taken=[],
                    execution_time_ms=duration,
                    status="success",
                    rollback_available=False,
                    success=True
                )
        except Exception as e:
            duration = int((time.time() - start_time) * 1000)
            return PlaybookResult(
                actions_taken=[],
                execution_time_ms=duration,
                status="failed",
                rollback_available=False,
                success=False,
                message="Playbook execution failed",
                error=str(e)
            )
