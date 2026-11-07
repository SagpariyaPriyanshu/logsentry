"""Save events and alerts to a SQLite database, and read them back."""
import json 
import sqlite3
import pandas as pd

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,          -- ISO 8601 text, e.g. 2026-10-07T14:00:00
    source     TEXT NOT NULL,          -- "auth" or "web"
    event_type TEXT NOT NULL,
    ip         TEXT,
    user       TEXT,
    details    TEXT,                   -- the details dict, stored as JSON text
    raw        TEXT NOT NULL,
    UNIQUE (ts, raw)                   -- the same log line is never stored twice
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    rule       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    message    TEXT NOT NULL,
    ip         TEXT,
    user       TEXT,
    evidence   TEXT,                   -- list of raw lines, stored as JSON text
    notified   INTEGER NOT NULL DEFAULT 0   -- 1 once sent to Discord (Phase 4)
);

CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events (ip, ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON alerts (ts);
"""


def init_db(path):
    """Open (or create) the database at `path`, make sure the tables exist, return the connection."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row      # rows can be read by column name: row["ip"]
    conn.executescript(SCHEMA)
    return conn

def save_events(conn, events):
    """Store events, skipping any already in the database. Returns how many were new."""
    rows = [
        (e.timestamp.isoformat(), e.source, e.event_type, e.ip, e.user,
         json.dumps(e.details), e.raw)
        for e in events
    ]
    before = conn.total_changes
    conn.executemany(
        "INSERT OR IGNORE INTO events (ts, source, event_type, ip, user, details, raw) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    return conn.total_changes - before

def already_alerted(conn, alert):
    """True if this exact alert (same rule, time and message) is already stored."""
    row = conn.execute(
        "SELECT 1 FROM alerts WHERE rule = ? AND ts = ? AND message = ? LIMIT 1",
        (alert.rule, alert.timestamp.isoformat(), alert.message),
    ).fetchone()
    return row is not None


def save_alerts(conn, alerts):
    """Store alerts we haven't stored before. Returns how many were new."""
    new_alerts = [a for a in alerts if not already_alerted(conn, a)]
    rows = [
        (a.timestamp.isoformat(), a.rule, a.severity, a.message, a.ip, a.user,
         json.dumps(a.evidence))
        for a in new_alerts
    ]
    conn.executemany(
        "INSERT INTO alerts (ts, rule, severity, message, ip, user, evidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    return len(new_alerts)

def load_events_df(conn, since=None):
    """Read events into a pandas DataFrame, oldest first. `since` limits it to newer events."""
    return _load_df(conn, "events", since)


def load_alerts_df(conn, since=None):
    """Read alerts into a pandas DataFrame, oldest first. `since` limits it to newer alerts."""
    return _load_df(conn, "alerts", since)


def _load_df(conn, table, since):
    query = f"SELECT * FROM {table}"     # table is always our own fixed name
    params = []
    if since is not None:
        query += " WHERE ts >= ?"
        params.append(since.isoformat())
    query += " ORDER BY ts"

    df = pd.read_sql(query, conn, params=params)
    df["ts"] = pd.to_datetime(df["ts"])  # text back into real timestamps
    return df