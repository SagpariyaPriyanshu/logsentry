"""Detection rules, and one function that runs them all."""
from logsentry.detectors.brute_force import detect_brute_force
from logsentry.detectors.privilege import detect_privilege_escalation
from logsentry.detectors.unusual_login import detect_unusual_login
from logsentry.detectors.web_scan import detect_web_scan

# Every detector takes (events, cfg) and returns a list of Alerts.
# To add a new rule, write it and add it to this list.
DETECTORS = [
    detect_brute_force,
    detect_privilege_escalation,
    detect_unusual_login,
    detect_web_scan,
]


def run_all_detectors(events, cfg):
    """Run every detector and return all alerts, oldest first."""
    alerts = []
    for detector in DETECTORS:
        alerts.extend(detector(events, cfg))
    return sorted(alerts, key=lambda a: a.timestamp)