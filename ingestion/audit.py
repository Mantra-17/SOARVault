"""
ingestion/audit.py
------------------
Structured audit logging for the SOARVault ingestion pipeline.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

AUDIT_LOG_FILE = Path("audit.log")

class AuditLogger:
    """Maintains an append-only log of critical system events."""
    def __init__(self, log_file: Path = AUDIT_LOG_FILE):
        self.log_file = log_file
        if not self.log_file.exists():
            self.log_file.touch()

    def log_event(self, event_type: str, actor: str, details: Dict[str, Any]) -> None:
        """Appends a structured JSON event to the audit log."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "actor": actor,
            "details": details
        }
        try:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Reads the most recent structured audit logs from the file."""
        if not self.log_file.exists():
            return []
            
        logs = []
        try:
            with self.log_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            logs.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            logger.error(f"Failed to read audit log: {e}")
            
        return logs[-limit:]

# Global instance
audit_logger = AuditLogger()
