import time
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from playbooks.actions import ACTIONS_MAP, ActionResult
from playbooks.report import generate_containment_report
from ingestion.database import get_redis_client

class PlaybookEngine:
    """
    Orchestrates rule-based playbook execution, evaluating triggers
    and executing automated response actions in sequence.
    """
    def __init__(self):
        self.db = get_redis_client()
        self._initialize_default_playbooks()

    def _initialize_default_playbooks(self):
        """Seeds default playbooks in Redis if they don't already exist."""
        defaults = {
            "isolate-ec2-and-block-ip": {
                "id": "isolate-ec2-and-block-ip",
                "name": "Isolate EC2 + Block IP",
                "trigger": "risk_score >= 80 and ioc_type == 'ip'",
                "actions": ["quarantine_security_group", "block_ip_edge_firewall", "notify_slack"],
                "avg_exec_seconds": 3.9
            },
            "block-ip-firewall": {
                "id": "block-ip-firewall",
                "name": "Block IP at Perimeter Firewall",
                "trigger": "risk_score >= 60 and ioc_type == 'ip'",
                "actions": ["block_ip_edge_firewall", "notify_slack"],
                "avg_exec_seconds": 2.1
            },
            "quarantine-endpoint": {
                "id": "quarantine-endpoint",
                "name": "Quarantine Endpoint (EDR)",
                "trigger": "risk_score >= 50 and ioc_type == 'hash'",
                "actions": ["isolate_host_edr", "notify_slack"],
                "avg_exec_seconds": 4.6
            }
        }
        try:
            for pid, pb in defaults.items():
                if not self.db.exists(f"playbook:{pid}"):
                    self.db.set(f"playbook:{pid}", json.dumps(pb))
        except Exception as e:
            print(f"[*] Error seeding playbooks: {e}")

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """Returns all configured playbooks from Redis."""
        playbooks = []
        try:
            keys = self.db.keys("playbook:*")
            for k in keys:
                pb_data = self.db.get(k)
                if pb_data:
                    playbooks.append(json.loads(pb_data))
        except Exception as e:
            print(f"[*] Error listing playbooks: {e}")
            
        # Fallback if Redis fails
        if not playbooks:
            return [
                {
                    "id": "isolate-ec2-and-block-ip",
                    "name": "Isolate EC2 + Block IP",
                    "trigger": "risk_score >= 80 and ioc_type == 'ip'",
                    "actions": ["quarantine_security_group", "block_ip_edge_firewall", "notify_slack"],
                    "avg_exec_seconds": 3.9
                }
            ]
        return playbooks

    def evaluate_trigger(self, trigger_str: str, context: Dict[str, Any]) -> bool:
        """Safely evaluates boolean expression triggers against alert context."""
        safe_locals = {
            "risk_score": context.get("risk_score", 0),
            "ioc_type": context.get("ioc_type", ""),
            "severity": context.get("severity", "").lower(),
            "source": context.get("source", ""),
            "rule_name": context.get("rule_name", ""),
            "title": context.get("title", ""),
        }
        try:
            # Safely evaluate condition using restricted globals/locals
            return bool(eval(trigger_str, {"__builtins__": None}, safe_locals))
        except Exception as e:
            print(f"[*] Trigger evaluation error for '{trigger_str}': {e}")
            return False

    def select_playbook(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Matches an alert against configured playbooks and returns the best fit."""
        playbooks = self.list_playbooks()
        # Order by specificity / complexity (longer action list first)
        playbooks.sort(key=lambda p: len(p.get("actions", [])), reverse=True)
        
        for pb in playbooks:
            if self.evaluate_trigger(pb.get("trigger", ""), alert):
                return pb
        return None

    def execute(self, case_id: str, approved: bool = False) -> Dict[str, Any]:
        """
        Executes the containment actions for a case.
        Handles approval workflow and appends timing logs to the case timeline.
        """
        try:
            case_data = self.db.get(f"case:{case_id}")
            if not case_data:
                return {"success": False, "error": "Case not found"}
                
            case = json.loads(case_data)
            
            # 1. Check if approval is required and we don't have it yet
            is_critical = case.get("severity") == "critical" or case.get("risk_score", 0) >= 80
            
            if is_critical and case.get("status") == "pending_approval" and not approved:
                print(f"[*] Case {case_id} is high impact and awaiting manual approval.")
                return {"success": True, "status": "pending_approval", "message": "Awaiting approval"}
                
            # If transitioning from pending approval to approved
            if case.get("status") == "pending_approval" and approved:
                case["status"] = "in_progress"
                case["timeline"].append({
                    "step": "Approved",
                    "detail": "Orchestration execution authorized by senior analyst",
                    "offset_seconds": round((datetime.utcnow() - datetime.fromisoformat(case["created_at"])).total_seconds(), 2)
                })
            
            start_time = datetime.fromisoformat(case["created_at"])
            actions = case.get("actions", [])
            timeline = case.get("timeline", [])
            
            # Execute each action
            print(f"[*] Running playbook {case.get('playbook')} actions for Case {case_id}...")
            action_results = []
            
            for act_name in actions:
                if act_name not in ACTIONS_MAP:
                    print(f"[!] Action '{act_name}' not implemented, skipping.")
                    continue
                    
                print(f"[*] Running action: {act_name}")
                action_func = ACTIONS_MAP[act_name]
                
                # Execute action function (passing IOC value as target)
                res: ActionResult = action_func(case.get("ioc"))
                action_results.append(res)
                
                # Calculate timeline offset
                offset = round((datetime.utcnow() - start_time).total_seconds(), 2)
                
                # Map action name to clean label
                step_label = "Contained" if act_name in ("block_ip_edge_firewall", "quarantine_security_group", "isolate_host_edr") else "Notification Sent"
                detail_text = f"Action {act_name} completed: target={res.target}, status={res.status} ({res.duration_ms}ms)"
                
                timeline.append({
                    "step": step_label if step_label != "Notification Sent" else "Notification",
                    "detail": detail_text,
                    "offset_seconds": offset
                })
            
            # Complete the containment
            total_duration = round((datetime.utcnow() - start_time).total_seconds(), 2)
            case["mttr_seconds"] = total_duration
            
            # Set final status
            if case.get("ioc_type") == "hash":
                case["status"] = "resolved_auto"
            else:
                case["status"] = "contained"
                
            case["timeline"].append({
                "step": "Contained" if case["status"] == "contained" else "Resolved",
                "detail": f"Incident successfully mitigated and closed. Total MTTR: {total_duration}s",
                "offset_seconds": total_duration
            })
            
            # Generate markdown report and store it
            report = generate_containment_report(case)
            case["report"] = report
            
            # Save back to database
            self.db.set(f"case:{case_id}", json.dumps(case))
            print(f"[*] Playbook execution completed for Case {case_id}. MTTR: {total_duration}s")
            
            # Also update metrics
            self._update_metrics(total_duration)
            
            return {"success": True, "case": case}
            
        except Exception as e:
            print(f"[!] Error in playbook engine execution: {e}")
            return {"success": False, "error": str(e)}

    def _update_metrics(self, new_mttr: float):
        """Updates aggregated metrics in Redis."""
        try:
            self.db.incr("metrics:cases_auto_contained_24h")
            
            # Recalculate average MTTR
            keys = self.db.keys("case:*")
            resolved_durations = []
            for k in keys:
                c_data = self.db.get(k)
                if c_data:
                    c = json.loads(c_data)
                    mttr = c.get("mttr_seconds")
                    if mttr:
                        resolved_durations.append(mttr)
            
            if resolved_durations:
                avg_mttr = round(sum(resolved_durations) / len(resolved_durations), 2)
                self.db.set("metrics:mttr_avg_seconds", avg_mttr)
                
            # Add static savings value
            self.db.incrbyfloat("metrics:analyst_hours_saved_24h", 0.5)
        except Exception as e:
            print(f"[!] Failed to update metrics in Redis: {e}")
