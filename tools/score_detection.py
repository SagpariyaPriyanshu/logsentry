"""Score LogSentry's detectors against the attacks we hid in the sample logs.

Run from the project folder:  python -m tools.score_detection
"""
from datetime import datetime, timedelta

from logsentry.config import load_config
from logsentry.detectors import run_all_detectors
from logsentry.parsers.auth_log import parse_auth_file
from logsentry.parsers.web_log import parse_web_file

# The answer key: the attacks generate_sample_logs.py hides in the logs.
# An alert "detects" an attack if its rule is one of `rules`, it names one of
# `who` (as its IP or user), and it starts within MATCH_WINDOW of `time`.
ANSWER_KEY = [
    {"name": "1. Brute force, then bob compromised",
     "rules": {"brute_force", "unusual_login"},
     "who": {"203.0.113.45"}, "time": datetime(2026, 10, 7, 14, 0)},
    {"name": "2. Backdoor admin account",
     "rules": {"privilege_escalation"},
     "who": {"bob", "backdoor"}, "time": datetime(2026, 10, 7, 14, 5)},
    {"name": "3. Charlie at 3 a.m.",
     "rules": {"unusual_login"},
     "who": {"charlie"}, "time": datetime(2026, 10, 9, 3, 12)},
    {"name": "4. Nikto web scan",
     "rules": {"web_scan", "web_attack_signature"},
     "who": {"198.51.100.23"}, "time": datetime(2026, 10, 8, 22, 30)},
    {"name": "5. sqlmap SQL injection",
     "rules": {"web_attack_signature"},
     "who": {"198.51.100.77"}, "time": datetime(2026, 10, 10, 2, 5)},
]
MATCH_WINDOW = timedelta(minutes=10)


def matches(alert, attack):
    """Does this alert describe this attack?"""
    return (alert.rule in attack["rules"]
            and (alert.ip in attack["who"] or alert.user in attack["who"])
            and abs(alert.timestamp - attack["time"]) <= MATCH_WINDOW)


def main():
    cfg = load_config()
    auth_events, _ = parse_auth_file("sample_logs/auth.log", year=2026)
    web_events, _ = parse_web_file("sample_logs/access.log")
    alerts = run_all_detectors(auth_events + web_events, cfg)

    print(f"{len(alerts)} alerts raised\n")
    detected = 0
    for attack in ANSWER_KEY:
        found = [a for a in alerts if matches(a, attack)]
        if found:
            detected += 1
        status = f"DETECTED ({len(found)} alerts)" if found else "MISSED"
        print(f"  {attack['name']:<40} {status}")

    false_positives = [a for a in alerts
                       if not any(matches(a, attack) for attack in ANSWER_KEY)]

    print(f"\nDetected:        {detected}/{len(ANSWER_KEY)}")
    print(f"False positives: {len(false_positives)}")
    for alert in false_positives:
        print(f"  {alert.timestamp}  {alert.rule}: {alert.message}")


if __name__ == "__main__":
    main()