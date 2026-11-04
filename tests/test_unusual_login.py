from datetime import datetime, timedelta

from logsentry.config import DEFAULTS
from logsentry.detectors.unusual_login import detect_unusual_login
from logsentry.models import Event

MONDAY = datetime(2026, 10, 5)


def login(day, hour, user="charlie", ip="10.0.0.13"):
    ts = MONDAY + timedelta(days=day, hours=hour)
    return Event(timestamp=ts, source="auth", event_type="login_success",
                 raw=f"Accepted password for {user} from {ip} at {ts}", ip=ip, user=user)


def normal_week(user="charlie", ip="10.0.0.13"):
    return [login(day, 9, user, ip) for day in range(5)]   # Mon-Fri at 9:00


def test_normal_work_logins_are_quiet():
    assert detect_unusual_login(normal_week(), DEFAULTS) == []


def test_3am_login_alerts():
    alerts = detect_unusual_login(normal_week() + [login(4, 3)], DEFAULTS)
    assert len(alerts) == 1
    assert "outside work hours (03:00)" in alerts[0].message


def test_new_ip_after_learning_alerts_once():
    events = normal_week() + [login(5, 10, ip="198.51.100.9"), login(6, 10, ip="198.51.100.9")]
    alerts = detect_unusual_login(events, DEFAULTS)
    assert len(alerts) == 1
    assert "new IP 198.51.100.9" in alerts[0].message


def test_new_ip_during_learning_is_just_learned():
    events = [login(0, 9), login(1, 9, ip="10.0.0.99")]   # day 2, still learning
    assert detect_unusual_login(events, DEFAULTS) == []


def test_ips_are_learned_per_user():
    # alice's usual IP is new for charlie
    events = normal_week() + normal_week("alice", "10.0.0.11") + [login(6, 10, ip="10.0.0.11")]
    alerts = detect_unusual_login(events, DEFAULTS)
    assert len(alerts) == 1 and alerts[0].user == "charlie"