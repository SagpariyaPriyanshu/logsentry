from datetime import datetime, timedelta

from logsentry.config import DEFAULTS
from logsentry.detectors.brute_force import detect_brute_force
from logsentry.models import Event

START = datetime(2026, 10, 7, 14, 0, 0)
ATTACKER = "203.0.113.45"


def failed(seconds, ip=ATTACKER, user="admin"):
    return Event(timestamp=START + timedelta(seconds=seconds), source="auth",
                 event_type="login_failed", raw=f"failed {user} from {ip} at +{seconds}s",
                 ip=ip, user=user)


def success(seconds, ip=ATTACKER, user="bob"):
    return Event(timestamp=START + timedelta(seconds=seconds), source="auth",
                 event_type="login_success", raw=f"accepted {user} from {ip}",
                 ip=ip, user=user)


def test_alerts_on_fast_failures():
    events = [failed(i * 3) for i in range(10)]
    alerts = detect_brute_force(events, DEFAULTS)
    assert len(alerts) == 1
    assert alerts[0].ip == ATTACKER
    assert alerts[0].severity == "high"
    assert len(alerts[0].evidence) == 10


def test_no_alert_for_a_few_typos():
    events = [failed(0, ip="10.0.0.12", user="bob"), success(10, ip="10.0.0.12")]
    assert detect_brute_force(events, DEFAULTS) == []


def test_failures_from_different_ips_are_not_combined():
    events = [failed(i, ip=f"10.0.0.{i}") for i in range(10)]   # 10 IPs, 1 failure each
    assert detect_brute_force(events, DEFAULTS) == []


def test_successful_login_after_attack_is_flagged():
    events = [failed(i * 3) for i in range(10)] + [success(40)]
    alert = detect_brute_force(events, DEFAULTS)[0]
    assert "SUCCESSFUL" in alert.message
    assert alert.user == "bob"
    assert alert.evidence[-1] == "accepted bob from 203.0.113.45"


def test_success_from_another_ip_is_not_blamed_on_attacker():
    events = [failed(i * 3) for i in range(10)] + [success(40, ip="10.0.0.12")]
    alert = detect_brute_force(events, DEFAULTS)[0]
    assert "SUCCESSFUL" not in alert.message