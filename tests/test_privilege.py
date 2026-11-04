from datetime import datetime

from logsentry.config import DEFAULTS, merge
from logsentry.detectors.privilege import detect_privilege_escalation
from logsentry.models import Event

CFG = merge(DEFAULTS, {"privilege": {"sudo_allowlist": ["alice"]}})
TS = datetime(2026, 10, 7, 14, 5, 0)


def event(event_type, user, **details):
    return Event(timestamp=TS, source="auth", event_type=event_type,
                 raw=f"{event_type} {user} {details}", user=user, details=details)


def test_sudo_by_allowlisted_admin_is_fine():
    events = [event("sudo", "alice", command="/usr/bin/apt update")]
    assert detect_privilege_escalation(events, CFG) == []


def test_sudo_by_other_user_alerts():
    events = [event("sudo", "bob", command="/usr/sbin/useradd -m backdoor")]
    alerts = detect_privilege_escalation(events, CFG)
    assert len(alerts) == 1
    assert alerts[0].user == "bob"
    assert "useradd" in alerts[0].message


def test_new_user_alerts():
    alerts = detect_privilege_escalation([event("user_added", "backdoor")], CFG)
    assert alerts[0].message == "New user account created: backdoor"


def test_added_to_sudo_group_alerts():
    events = [event("group_added", "backdoor", group="sudo")]
    assert len(detect_privilege_escalation(events, CFG)) == 1


def test_added_to_normal_group_is_fine():
    events = [event("group_added", "carol", group="developers")]
    assert detect_privilege_escalation(events, CFG) == []


def test_logins_are_ignored():
    assert detect_privilege_escalation([event("login_success", "bob")], CFG) == []