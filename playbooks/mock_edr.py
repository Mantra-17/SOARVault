import time
import random
from typing import Dict

class MockEDR:
    """
    Simulates a real EDR API with methods to isolate, scan, and check status.
    """
    def __init__(self):
        self._host_states = {}

    def isolate(self, host_id: str) -> Dict[str, str]:
        """
        Isolates a host.
        """
        time.sleep(random.uniform(0.1, 0.3)) # Simulate API delay
        self._host_states[host_id] = "isolated"
        return {"host_id": host_id, "status": "isolated", "message": "Host successfully isolated."}

    def scan(self, host_id: str) -> Dict[str, str]:
        """
        Initiates a scan on a host.
        """
        time.sleep(random.uniform(0.05, 0.2))
        return {"host_id": host_id, "scan_status": "started", "message": "Scan initiated."}

    def get_status(self, host_id: str) -> Dict[str, str]:
        """
        Gets the current status of a host.
        """
        time.sleep(random.uniform(0.05, 0.1))
        status = self._host_states.get(host_id, "connected")
        return {"host_id": host_id, "status": status}
