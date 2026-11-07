from datetime import datetime

from logsentry.alerts import DISCORD_LIMIT, format_alert
from logsentry.models import Alert

TS = datetime(2026, 10, 7, 14, 0, 0)


def make_alert(evidence, **overrides):
    fields = dict(timestamp=TS, rule="brute_force", severity="high",
                  message="40 failed logins from 203.0.113.45", ip="203.0.113.45",
                  evidence=evidence)
    fields.update(overrides)
    return Alert(**fields)


def test_message_has_the_key_facts():
    text = format_alert(make_alert(["line 1", "line 2"]))
    assert "HIGH" in text
    assert "brute_force" in text
    assert "203.0.113.45" in text
    assert "2026-10-07 14:00:00" in text
    assert "line 2" in text


def test_only_first_three_evidence_lines_are_shown():
    text = format_alert(make_alert([f"line {i}" for i in range(40)]))
    assert "line 2" in text
    assert "line 3" not in text
    assert "and 37 more lines" in text


def test_never_longer_than_discord_allows():
    huge = ["x" * 5000] * 3
    text = format_alert(make_alert(huge, message="y" * 5000))
    assert len(text) <= DISCORD_LIMIT


def test_no_ip_line_when_alert_has_no_ip():
    text = format_alert(make_alert(["sudo line"], ip=None, user="bob",
                                   rule="privilege_escalation"))
    assert "IP:" not in text
    assert "`bob`" in text