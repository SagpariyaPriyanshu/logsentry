"""Detect brute-force login attacks: many failed logins from one IP, fast."""
from collections import defaultdict
from datetime import timedelta

from logsentry.detectors.bursts import find_bursts
from logsentry.models import Alert

# How long after an attack we keep watching for the attacker getting in.
SUCCESS_LOOKAHEAD = timedelta(hours=1)


def detect_brute_force(events, cfg):
    """Return one high-severity Alert per burst of failed logins from one IP."""
    settings = cfg["brute_force"]

    # 1. Group failed logins by the IP they came from.
    failures_by_ip = defaultdict(list)
    for event in events:
        if event.event_type == "login_failed" and event.ip:
            failures_by_ip[event.ip].append(event)

    alerts = []
    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e.timestamp)

        # 2. Look for bursts in this IP's failures.
        for burst in find_bursts(failures, settings["max_failures"],
                                 settings["window_minutes"]):
            first, last = burst[0], burst[-1]
            seconds = int((last.timestamp - first.timestamp).total_seconds())
            users_tried = sorted({e.user for e in burst if e.user})

            message = (f"{len(burst)} failed logins from {ip} in {seconds}s "
                       f"(users tried: {', '.join(users_tried)})")
            evidence = [e.raw for e in burst]
            user = None

            # 3. Did the attacker then get in? That's much worse.
            success = find_success_after(events, ip, last.timestamp)
            if success:
                message += f", then a SUCCESSFUL login as {success.user}: account likely compromised"
                evidence.append(success.raw)
                user = success.user

            alerts.append(Alert(
                timestamp=first.timestamp,
                rule="brute_force",
                severity="high",
                message=message,
                ip=ip,
                user=user,
                evidence=evidence,
            ))
    return alerts


def find_success_after(events, ip, after):
    """Return the first successful login from `ip` soon after `after`, or None."""
    successes = [
        e for e in events
        if e.event_type == "login_success" and e.ip == ip
        and after <= e.timestamp <= after + SUCCESS_LOOKAHEAD
    ]
    return min(successes, key=lambda e: e.timestamp, default=None)