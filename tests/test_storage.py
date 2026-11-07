import json
from datetime import datetime

from logsentry.models import Alert, Event
from logsentry.storage import (already_alerted, init_db, load_alerts_df, load_events_df, save_alerts, save_events)

TS = datetime(2026, 10, 7, 14, 0, 0)


def table_names(conn):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    return {row["name"] for row in rows}


def make_event(ip="203.0.113.45", raw="Failed password for root from 203.0.113.45"):
    return Event(timestamp=TS, source="auth", event_type="login_failed", raw=raw,
                 ip=ip, user="root", details={"host": "web01"})


def count(conn, table):
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_init_db_creates_tables():
    conn = init_db(":memory:")
    assert {"events", "alerts"} <= table_names(conn)


def test_init_db_twice_is_safe(tmp_path):
    path = tmp_path / "test.db"
    init_db(path).close()
    conn = init_db(path)    # second time: IF NOT EXISTS means no error
    assert {"events", "alerts"} <= table_names(conn)


def test_saving_same_events_twice_stores_them_once():
    conn = init_db(":memory:")
    events = [make_event(raw=f"line {i}") for i in range(3)]
    assert save_events(conn, events) == 3
    assert save_events(conn, events) == 0      # all duplicates, all skipped
    assert count(conn, "events") == 3


def test_event_fields_round_trip():
    conn = init_db(":memory:")
    save_events(conn, [make_event()])
    row = conn.execute("SELECT * FROM events").fetchone()
    assert row["ts"] == "2026-10-07T14:00:00"
    assert row["ip"] == "203.0.113.45"
    assert json.loads(row["details"]) == {"host": "web01"}


def test_sql_injection_is_stored_as_plain_text():
    conn = init_db(":memory:")
    evil = "1.2.3.4'); DROP TABLE events;--"
    save_events(conn, [make_event(ip=evil)])
    assert "events" in table_names(conn)        # the table still exists
    assert conn.execute("SELECT ip FROM events").fetchone()["ip"] == evil


def test_save_alerts():
    conn = init_db(":memory:")
    alert = Alert(timestamp=TS, rule="brute_force", severity="high",
                  message="40 failed logins", ip="203.0.113.45",
                  evidence=["line 1", "line 2"])
    assert save_alerts(conn, [alert]) == 1
    row = conn.execute("SELECT * FROM alerts").fetchone()
    assert row["notified"] == 0
    assert json.loads(row["evidence"]) == ["line 1", "line 2"]

def make_alert(message="40 failed logins", ts=TS):
    return Alert(timestamp=ts, rule="brute_force", severity="high",
                 message=message, ip="203.0.113.45")


def test_already_alerted():
    conn = init_db(":memory:")
    assert not already_alerted(conn, make_alert())
    save_alerts(conn, [make_alert()])
    assert already_alerted(conn, make_alert())


def test_saving_same_alerts_twice_stores_them_once():
    conn = init_db(":memory:")
    alerts = [make_alert(), make_alert("New user account created: backdoor")]
    assert save_alerts(conn, alerts) == 2
    assert save_alerts(conn, alerts) == 0
    assert count(conn, "alerts") == 2


def test_similar_alert_at_another_time_is_kept():
    conn = init_db(":memory:")
    save_alerts(conn, [make_alert()])
    next_day = TS.replace(day=8)
    assert save_alerts(conn, [make_alert(ts=next_day)]) == 1

def test_load_events_df():
    conn = init_db(":memory:")
    save_events(conn, [make_event(raw="line 1"), make_event(raw="line 2")])
    df = load_events_df(conn)
    assert len(df) == 2
    assert df["ts"].iloc[0] == TS          # a real timestamp again, not text


def test_load_alerts_df_since():
    conn = init_db(":memory:")
    save_alerts(conn, [make_alert(), make_alert(ts=TS.replace(day=8))])
    df = load_alerts_df(conn, since=TS.replace(day=8))
    assert len(df) == 1
    assert df["ts"].iloc[0].day == 8