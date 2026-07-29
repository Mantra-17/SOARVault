"""
Threat actor profiling module.
Tracks historical attacks by IP in memory to identify repeat attackers.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime

# In-memory dictionary tracking seen IPs and their attack timestamps
# Format: {ip: [timestamps of attacks]}
_SEEN_IPS: Dict[str, List[str]] = {}


def track_and_check_ip(ip: Optional[str], timestamp: Optional[Any]) -> bool:
    """
    Record an attack timestamp for an IP address and check if it is a repeat attacker.
    An IP is flagged as a repeat attacker if it has attacked 3 or more times.
    
    Args:
        ip: The IP address to track.
        timestamp: The timestamp of the attack (datetime object, string, or None).
        
    Returns:
        True if the IP has been seen 3+ times, False otherwise.
    """
    if not ip:
        return False
        
    if timestamp is None:
        # Fallback to current time if no timestamp is provided
        timestamp = datetime.now()
        
    # Standardize timestamp to ISO format string
    if isinstance(timestamp, datetime):
        ts_str = timestamp.isoformat()
    else:
        ts_str = str(timestamp)
        
    if ip not in _SEEN_IPS:
        _SEEN_IPS[ip] = []
        
    if ts_str not in _SEEN_IPS[ip]:
        _SEEN_IPS[ip].append(ts_str)
        
    return len(_SEEN_IPS[ip]) >= 3


def get_attack_history(ip: str) -> List[str]:
    """
    Get the recorded attack timestamps for a given IP.
    
    Args:
        ip: The IP address.
        
    Returns:
        A list of ISO format timestamp strings.
    """
    return _SEEN_IPS.get(ip, [])


def clear_threat_actor_history() -> None:
    """
    Clear all recorded threat actor profiling history.
    """
    _SEEN_IPS.clear()
