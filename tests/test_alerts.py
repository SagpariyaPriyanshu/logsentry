from datetime import datetime
from unittest.mock import Mock, patch
import requests
from logsentry.alerts import DISCORD_LIMIT, format_alert, send_discord, dispatch
from logsentry.models import Alert
from logsentry.storage import init_db, save_alerts

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

URL = "https://discord.com/api/webhooks/123/fake"


def fake_response(status, body=None):
    response = Mock()
    response.status_code = status
    response.ok = 200 <= status < 300
    response.json.return_value = body or {}
    return response


@patch("logsentry.alerts.requests.post")
def test_send_success(mock_post):
    mock_post.return_value = fake_response(204)
    assert send_discord(URL, "hello") is True
    sent = mock_post.call_args.kwargs
    assert sent["json"]["content"] == "hello"
    assert sent["json"]["allowed_mentions"] == {"parse": []}
    assert sent["timeout"] == 5


@patch("logsentry.alerts.requests.post")
def test_send_rejected_returns_false(mock_post):
    mock_post.return_value = fake_response(404)
    assert send_discord(URL, "hello") is False


@patch("logsentry.alerts.requests.post")
def test_network_error_returns_false_instead_of_crashing(mock_post):
    mock_post.side_effect = requests.ConnectionError("no internet")
    assert send_discord(URL, "hello") is False


@patch("logsentry.alerts.time.sleep")
@patch("logsentry.alerts.requests.post")
def test_rate_limit_waits_then_retries(mock_post, mock_sleep):
    mock_post.side_effect = [fake_response(429, {"retry_after": 1.5}), fake_response(204)]
    assert send_discord(URL, "hello") is True
    mock_sleep.assert_called_once_with(1.5)
    assert mock_post.call_count == 2


def db_with(*severities):
    conn = init_db(":memory:")
    save_alerts(conn, [make_alert([f"line {i}"], severity=s, message=f"alert {i}")
                       for i, s in enumerate(severities)])
    return conn


@patch("logsentry.alerts.send_discord", return_value=True)
def test_dispatch_sends_only_high_alerts(mock_send):
    conn = db_with("high", "medium", "high")
    assert dispatch(conn, URL, "high") == 2
    assert mock_send.call_count == 2


@patch("logsentry.alerts.send_discord", return_value=True)
def test_dispatch_never_sends_twice(mock_send):
    conn = db_with("high")
    assert dispatch(conn, URL, "high") == 1
    assert dispatch(conn, URL, "high") == 0
    assert mock_send.call_count == 1


@patch("logsentry.alerts.send_discord", return_value=False)
def test_failed_send_is_retried_next_time(mock_send):
    conn = db_with("high")
    assert dispatch(conn, URL, "high") == 0
    mock_send.return_value = True
    assert dispatch(conn, URL, "high") == 1


@patch("logsentry.alerts.send_discord", return_value=True)
def test_lower_threshold_sends_medium_too(mock_send):
    conn = db_with("high", "medium", "low")
    assert dispatch(conn, URL, "medium") == 2