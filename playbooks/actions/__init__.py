from dataclasses import dataclass

@dataclass
class ActionResult:
    action: str
    target: str
    status: str
    timestamp: str
    duration_ms: int
    reversible: bool

from .aws_block import quarantine_security_group
from .block_ip import block_ip_edge_firewall
from .block_outbound import block_outbound_traffic
from .disable_account import disable_user_account
from .isolate_host import isolate_host_edr
from .send_alert import send_notification, notify_slack

# Map of action names to functions
ACTIONS_MAP = {
    "quarantine_security_group": quarantine_security_group,
    "block_ip_edge_firewall": block_ip_edge_firewall,
    "block_outbound_traffic": block_outbound_traffic,
    "disable_user_account": disable_user_account,
    "isolate_host_edr": isolate_host_edr,
    "send_notification": send_notification,
    "notify_slack": notify_slack
}
