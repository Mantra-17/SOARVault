"""
Execution report generator for SOARVault playbooks.
"""
from typing import Dict, Any, Optional
from .engine import PlaybookEngine

def get_execution_report(engine: PlaybookEngine, case_id: str) -> Optional[Dict[str, Any]]:
    """
    Generates an execution summary per incident.
    """
    if case_id not in engine.cases:
        return None
        
    result = engine.cases[case_id]
    
    actions_taken = []
    for action in result.actions_taken:
        actions_taken.append({
            "action": getattr(action, "action", "unknown"),
            "target": getattr(action, "target", "unknown"),
            "status": getattr(action, "status", "unknown"),
            "duration_ms": getattr(action, "duration_ms", 0),
            "timestamp": getattr(action, "timestamp", "")
        })
        
    report = {
        "case_id": case_id,
        "playbook_name": result.message.replace("Successfully routed and executed playbook for: ", "") if result.message else "Unknown Playbook",
        "status": result.status,
        "total_time_ms": result.execution_time_ms,
        "rollback_available": result.rollback_available,
        "actions_taken": actions_taken,
        "error": result.error
    }
    
    return report
