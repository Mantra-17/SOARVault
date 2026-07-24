from playbooks.actions import ACTIONS_MAP, ActionResult

class BruteForcePlaybook:
    id = "brute-force-lockout"
    name = "Brute Force Lockout"
    default_trigger = "risk_score >= 70 and ioc_type == 'ip'"
    default_actions = ["disable_user_account", "block_ip_edge_firewall", "notify_slack"]
    
    @classmethod
    def run(cls, target: str) -> list:
        results = []
        for act_name in cls.default_actions:
            if act_name in ACTIONS_MAP:
                results.append(ACTIONS_MAP[act_name](target))
        return results
