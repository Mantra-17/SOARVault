"""
rbac.py — Role-Based Access Control

Two personas from the project brief:
  - soc_analyst: reviews the dashboard, triages/acknowledges alerts,
    cannot edit playbooks.
  - security_engineer: everything soc_analyst can do, plus
    write/edit/publish playbooks and trigger manual containment actions.

This is a placeholder used by the frontend team to shape the UI
(which buttons/tabs render per role). The backend team will wire this
to real auth (SSO / JWT) later.
"""

ROLES = {
    "soc_analyst": {
        "label": "SOC Analyst",
        "permissions": [
            "view_dashboard",
            "view_alerts",
            "acknowledge_alert",
            "escalate_alert",
            "view_playbooks",
        ],
    },
    "security_engineer": {
        "label": "Security Engineer",
        "permissions": [
            "view_dashboard",
            "view_alerts",
            "acknowledge_alert",
            "escalate_alert",
            "view_playbooks",
            "edit_playbook",
            "publish_playbook",
            "trigger_manual_containment",
        ],
    },
}


def get_role(role_key: str) -> dict:
    return ROLES.get(role_key, ROLES["soc_analyst"])


def has_permission(role_key: str, permission: str) -> bool:
    return permission in get_role(role_key)["permissions"]
