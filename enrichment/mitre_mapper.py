"""enrichment/mitre_mapper.py
--------------------------
MITRE ATT&CK mapping integration for SOARVault.
Keep mappings easily extendable via dictionary lookup or configuration.
Fulfills Day 23 requirements.
"""

import os
import json
from typing import Any, Dict, List, Optional

# Default built-in mappings based on alert type or category
_DEFAULT_MAPPINGS: Dict[str, Dict[str, Any]] = {
    # Brute Force mappings
    "ssh_brute_force": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access accounts by guessing passwords without account knowledge.",
        "reference": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "rdp_brute_force_external": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access accounts by guessing passwords for RDP authentication endpoints.",
        "reference": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "splunk_bruteforce": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force mechanisms to gain access to corporate systems.",
        "reference": "https://attack.mitre.org/techniques/T1110/"
    },
    
    # Malware & Ransomware mappings
    "malware_lockbit": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability of system and network resources.",
        "reference": "https://attack.mitre.org/techniques/T1486/"
    },
    "malware_alert": {
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File (Malware)",
        "tactic": "Execution",
        "description": "An adversary may rely on a user opening a malicious file attachment or binary execution.",
        "reference": "https://attack.mitre.org/techniques/T1204/002/"
    },
    "ransomware_activity": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt local and remote directories using Lockbit or other ransomware payloads.",
        "reference": "https://attack.mitre.org/techniques/T1486/"
    },
    "qradar_malware": {
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "An adversary may rely on a user opening a malicious file attachment or binary execution.",
        "reference": "https://attack.mitre.org/techniques/T1204/002/"
    },
    
    # Command and Control mappings
    "c2_beaconing": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using standard web protocols (HTTP/HTTPS) to blend in with normal traffic.",
        "reference": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "tor_exit_node_activity": {
        "technique_id": "T1090.003",
        "technique_name": "Proxy: Multi-hop Proxy",
        "tactic": "Command and Control",
        "description": "Adversaries may use Tor exit nodes or multi-hop proxies to anonymize traffic origins and command pipelines.",
        "reference": "https://attack.mitre.org/techniques/T1090/003/"
    },
    
    # Cryptomining
    "cryptominer_execution": {
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "tactic": "Impact",
        "description": "Adversaries may leverage system compute resources to mine cryptocurrency without authorization.",
        "reference": "https://attack.mitre.org/techniques/T1496/"
    },
    
    # Exfiltration
    "data_exfil_ecs": {
        "technique_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate sensitive data over alternative non-C2 network protocols.",
        "reference": "https://attack.mitre.org/techniques/T1048/003/"
    },
    "crowdstrike_exfil": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate enterprise credentials, source code, or databases via web transfer APIs.",
        "reference": "https://attack.mitre.org/techniques/T1048/"
    },
    
    # Phishing
    "phishing_credential_harvest": {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails containing malicious URLs designed to harvest credentials.",
        "reference": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "phishing_o365": {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may execute credential harvesting campaigns disguised as O365 account renewal alerts.",
        "reference": "https://attack.mitre.org/techniques/T1566/002/"
    }
}


class MitreAttackMapper:
    """MITRE ATT&CK framework mapping resolver."""

    def __init__(self, custom_mapping_path: Optional[str] = None):
        self.mappings = dict(_DEFAULT_MAPPINGS)
        
        # Load custom external mappings if provided and exist
        if custom_mapping_path and os.path.exists(custom_mapping_path):
            try:
                with open(custom_mapping_path, "r", encoding="utf-8") as f:
                    custom = json.load(f)
                    if isinstance(custom, dict):
                        self.mappings.update(custom)
            except Exception as e:
                print(f"[*] Error loading custom MITRE mappings from {custom_mapping_path}: {e}")

    def get_mapping(self, alert_type: str, title: str = "") -> Optional[Dict[str, Any]]:
        """Resolves MITRE ATT&CK mapping based on alert type or title keywords.

        Args:
            alert_type: The normalized or raw alert type indicator.
            title: The alert title for fuzzy matches.

        Returns:
            A dictionary containing MITRE details, or None if no match.
        """
        # 1. Direct match on alert type
        if alert_type in self.mappings:
            return self.mappings[alert_type]

        # 2. Fuzzy checks on alert type or title strings
        norm_type = alert_type.lower()
        title_lower = title.lower() if title else ""
        
        for key, mapping in self.mappings.items():
            key_clean = key.lower().replace("_", " ")
            if key_clean in norm_type or key_clean in title_lower:
                return mapping
                
        if "brute" in norm_type or "brute" in title_lower:
            return self.mappings["splunk_bruteforce"]
        if "phish" in norm_type or "phish" in title_lower:
            return self.mappings["phishing_o365"]
        if "miner" in norm_type or "miner" in title_lower:
            return self.mappings["cryptominer_execution"]
        if "malware" in norm_type or "ransom" in norm_type or "malware" in title_lower or "ransom" in title_lower:
            return self.mappings["malware_lockbit"]
        if "c2" in norm_type or "beacon" in norm_type or "c2" in title_lower or "beacon" in title_lower or "connection" in title_lower:
            return self.mappings["c2_beaconing"]
        if "exfil" in norm_type or "exfil" in title_lower:
            return self.mappings["crowdstrike_exfil"]

        return None

