from playbooks.actions import ACTIONS_MAP, ActionResult

class DDoSPlaybook:
    id = "ddos-rate-limiting"
    name = "DDoS Rate Limiting & Blocking"
    default_trigger = "risk_score >= 75 and ioc_type == 'ip'"
    default_actions = ["block_ip_edge_firewall", "block_outbound_traffic", "notify_slack"]
    
    @classmethod
    def run(cls, target: str) -> list:
        results = []
        for act_name in cls.default_actions:
            if act_name in ACTIONS_MAP:
                results.append(ACTIONS_MAP[act_name](target))
        return results
