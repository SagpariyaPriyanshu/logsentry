"""Detect privilege escalation: new accounts, admin group changes, unexpected sudo."""
from logsentry.models import Alert

# Groups that give a user admin (root) powers on common Linux systems.
ADMIN_GROUPS = {"sudo", "admin", "wheel"}


def detect_privilege_escalation(events, cfg):
    """Return a high-severity Alert for each suspicious privilege change."""
    allowlist = set(cfg["privilege"]["sudo_allowlist"])
    alerts = []

    for event in events:
        message = None

        if event.event_type == "user_added":
            message = f"New user account created: {event.user}"

        elif event.event_type == "group_added":
            group = event.details.get("group")
            if group in ADMIN_GROUPS:
                message = f"User {event.user} added to admin group '{group}'"

        elif event.event_type == "sudo" and event.user not in allowlist:
            command = event.details.get("command", "?")
            message = f"sudo used by {event.user}, who is not on the allowlist: {command}"

        if message:
            alerts.append(Alert(
                timestamp=event.timestamp,
                rule="privilege_escalation",
                severity="high",
                message=message,
                ip=event.ip,
                user=event.user,
                evidence=[event.raw],
            ))
    return alerts