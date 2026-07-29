from playbooks.actions import ACTIONS_MAP, ActionResult

class InsiderThreatPlaybook:
    id = "insider-threat-mitigation"
    name = "Insider Threat Mitigation"
    default_trigger = "risk_score >= 65 and ioc_type == 'username'"
    default_actions = ["disable_user_account", "notify_slack"]
    
    @classmethod
    def run(cls, target: str) -> list:
        results = []
        for act_name in cls.default_actions:
            if act_name in ACTIONS_MAP:
                results.append(ACTIONS_MAP[act_name](target))
        return results
