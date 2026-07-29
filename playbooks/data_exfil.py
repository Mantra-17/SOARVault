from playbooks.actions import ACTIONS_MAP, ActionResult

class DataExfilPlaybook:
    id = "data-exfil-containment"
    name = "Data Exfiltration Containment"
    default_trigger = "risk_score >= 80 and ioc_type == 'ip'"
    default_actions = ["block_ip_edge_firewall", "quarantine_security_group", "notify_slack"]
    
    @classmethod
    def run(cls, target: str) -> list:
        results = []
        for act_name in cls.default_actions:
            if act_name in ACTIONS_MAP:
                results.append(ACTIONS_MAP[act_name](target))
        return results
