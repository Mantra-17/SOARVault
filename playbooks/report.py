from typing import Dict, Any
from .engine import PlaybookEngine

def get_execution_report(engine: PlaybookEngine, case_id: str) -> Dict[str, Any]:
    """
    Generate an execution summary for a specific case.
    """
    if case_id not in engine.case_history:
        return {"error": "Case not found"}
        
    result = engine.case_history[case_id]
    
    actions_summary = []
    for action in result.actions_taken:
        actions_summary.append({
            "action": action.action,
            "target": action.target,
            "status": action.status,
            "duration_ms": action.duration_ms
        })
        
    return {
        "case_id": case_id,
        "status": result.status,
        "total_execution_time_ms": result.execution_time_ms,
        "actions_taken": actions_summary,
        "rollback_available": result.rollback_available
    }
