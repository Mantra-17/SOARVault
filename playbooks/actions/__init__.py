from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class ActionResult:
    action: str
    target: str
    status: str
    timestamp: str
    duration_ms: int
    reversible: bool
