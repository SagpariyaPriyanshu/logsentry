"""Detect unusual logins: outside work hours, or from an IP the user never used before."""
from collections import defaultdict
from datetime import timedelta

from logsentry.models import Alert


def detect_unusual_login(events, cfg):
    """Return a medium-severity Alert for each successful login that breaks the user's normal pattern."""
    settings = cfg["unusual_login"]
    start_hour, end_hour = settings["work_hours"]

    logins = sorted((e for e in events if e.event_type == "login_success" and e.user),
                    key=lambda e: e.timestamp)
    if not logins:
        return []

    # The first few days are the "learning period": we only record what's normal.
    learning_ends = logins[0].timestamp + timedelta(days=settings["learning_days"])
    known_ips = defaultdict(set)    # user -> every IP we've seen them log in from

    alerts = []
    for login in logins:
        reasons = []

        hour = login.timestamp.hour
        if hour < start_hour or hour >= end_hour:
            reasons.append(f"outside work hours ({login.timestamp:%H:%M})")

        is_new_ip = login.ip and login.ip not in known_ips[login.user]
        if is_new_ip and login.timestamp >= learning_ends:
            reasons.append(f"from a new IP {login.ip}")

        if login.ip:
            known_ips[login.user].add(login.ip)   # learn it, so it only alerts once

        if reasons:
            alerts.append(Alert(
                timestamp=login.timestamp,
                rule="unusual_login",
                severity="medium",
                message=f"Unusual login for {login.user}: {' and '.join(reasons)}",
                ip=login.ip,
                user=login.user,
                evidence=[login.raw],
            ))
    return alerts