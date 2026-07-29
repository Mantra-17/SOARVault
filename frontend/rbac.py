"""
rbac.py — Role-Based Access Control & Password Authentication

3 role tiers:
  - analyst        : VIEW_ONLY
  - senior_analyst : VIEW + APPROVE
  - admin          : FULL_ACCESS
"""

import hashlib
import hmac
import os
from typing import Optional, Dict, Any

VIEW_ONLY = ["view"]
VIEW_APPROVE = ["view", "approve"]
FULL_ACCESS = ["view", "approve", "edit", "delete", "manage_users"]

ROLES: Dict[str, Dict[str, Any]] = {
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

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Generate a PBKDF2-HMAC-SHA256 salted hash string for a password."""
    if salt is None:
        salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"pbkdf2:sha256:100000${salt.hex()}${derived.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plain password against a stored PBKDF2 hash or plaintext string."""
    if not stored_hash:
        return False
    if stored_hash.startswith("pbkdf2:sha256:"):
        parts = stored_hash.split("$")
        if len(parts) != 3:
            return False
        _, salt_hex, derived_hex = parts
        salt = bytes.fromhex(salt_hex)
        expected_derived = bytes.fromhex(derived_hex)
        computed_derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(computed_derived, expected_derived)
    # Backward compatibility for plain strings during transition
    return hmac.compare_digest(password, stored_hash)

# User credentials store with PBKDF2 pre-hashed passwords
USERS: Dict[str, Dict[str, Any]] = {
    "asha.analyst": {
        "password": hash_password("demo123", salt=b"soarvault_salt_1"),
        "role": "analyst",
    },
    "rohit.senior": {
        "password": hash_password("demo123", salt=b"soarvault_salt_2"),
        "role": "senior_analyst",
    },
    "admin": {
        "password": hash_password("demo123", salt=b"soarvault_salt_3"),
        "role": "admin",
    },
}


def get_role(role_key: str) -> dict:
    return ROLES.get(role_key, ROLES["analyst"])


def has_permission(role: str, action: str) -> bool:
    return action in get_role(role)["permissions"]


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = USERS.get(username)
    if not user or not verify_password(password, user["password"]):
        return None
    return {
        "username": username,
        "role": user["role"],
        "role_label": get_role(user["role"])["label"],
    }
