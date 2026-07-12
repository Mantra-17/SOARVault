"""
rbac.py — Role-Based Access Control

3 role tiers:
  - analyst        : VIEW_ONLY
  - senior_analyst  : VIEW + APPROVE
  - admin          : FULL_ACCESS
"""

VIEW_ONLY = ["view"]
VIEW_APPROVE = ["view", "approve"]
FULL_ACCESS = ["view", "approve", "edit", "delete", "manage_users"]

ROLES = {
    "analyst": {
        "label": "Analyst",
        "permissions": VIEW_ONLY,
    },
    "senior_analyst": {
        "label": "Senior Analyst",
        "permissions": VIEW_APPROVE,
    },
    "admin": {
        "label": "Admin",
        "permissions": FULL_ACCESS,
    },
}

USERS = {
    "asha.analyst": {"password": "demo123", "role": "analyst"},
    "rohit.senior": {"password": "demo123", "role": "senior_analyst"},
    "admin": {"password": "demo123", "role": "admin"},
}


def get_role(role_key: str) -> dict:
    return ROLES.get(role_key, ROLES["analyst"])


def has_permission(role: str, action: str) -> bool:
    return action in get_role(role)["permissions"]


def authenticate(username: str, password: str):
    user = USERS.get(username)
    if not user or user["password"] != password:
        return None
    return {"username": username, "role": user["role"], "role_label": get_role(user["role"])["label"]}