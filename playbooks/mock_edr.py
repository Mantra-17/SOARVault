import time

class MockEDR:
    """Simulates a real EDR API."""
    def isolate(self, host_id: str) -> str:
        """Mock isolate call."""
        time.sleep(0.1)
        return "isolated"

    def scan(self, host_id: str) -> str:
        """Mock scan call."""
        time.sleep(0.2)
        return "clean"

    def get_status(self, host_id: str) -> str:
        """Mock get_status call."""
        return "online"
