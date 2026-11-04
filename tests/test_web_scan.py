from datetime import datetime, timedelta

from logsentry.config import DEFAULTS
from logsentry.detectors.web_scan import detect_web_scan
from logsentry.models import Event

START = datetime(2026, 10, 8, 22, 30, 0)
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def request(seconds, ip="198.51.100.23", path="/", status=200, agent=BROWSER):
    return Event(timestamp=START + timedelta(seconds=seconds), source="web",
                 event_type="http_request", raw=f"{ip} {path} {status}", ip=ip,
                 details={"path": path, "status": status, "agent": agent})


def test_burst_of_404s_alerts_once():
    events = [request(i * 2, path=f"/page{i}", status=404) for i in range(30)]
    alerts = detect_web_scan(events, DEFAULTS)
    assert [a.rule for a in alerts] == ["web_scan"]
    assert len(alerts[0].evidence) == 30


def test_occasional_404s_are_normal():
    events = [request(i * 3600, path="/favicon.ico", status=404) for i in range(30)]   # hourly
    assert detect_web_scan(events, DEFAULTS) == []


def test_attack_tool_user_agent_alerts():
    events = [request(i, path="/products.php?id=3", agent="sqlmap/1.8.11#stable") for i in range(3)]
    alerts = detect_web_scan(events, DEFAULTS)
    assert len(alerts) == 1
    assert "sqlmap" in alerts[0].message


def test_sql_injection_path_alerts_case_insensitive():
    events = [request(0, path="/products.php?id=3' or 1=1--")]
    assert len(detect_web_scan(events, DEFAULTS)) == 1


def test_normal_browsing_is_quiet():
    events = [request(i * 30, ip=f"192.0.2.{i}", path="/products") for i in range(50)]
    assert detect_web_scan(events, DEFAULTS) == []