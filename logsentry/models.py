"""Event and Alert dataclasses shared by every module. Built in Phase 1, step 1.1."""
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class Event:
    """One thing that happened , pasrsed from a single log line."""
    timestamp: datetime
    source: str                         # where it came from: "auth" or "web"
    event_type: str                     # what happened: "login_failed", "login_success", "sudo" ....
    raw: str                            # the original log line, kept as evidence
    ip: str | None = None
    user: str | None = None
    details: dict = field(default_factory=dict)

@dataclass
class Alert:
    """Something suspicious that a detector found."""
    timestamp: datetime
    rule: str                           # which detector fired: "brute_force", "web_scan", ...
    severity: str                       # how bad it is: "high", "medium", "low"
    message: str                        # human readable message
    ip: str | None = None
    user: str | None = None
    evidence: list[Event] = field(default_factory=list)  # the events that triggered this alert