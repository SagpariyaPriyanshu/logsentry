"""Save events and alerts to a SQLite database, and read them back."""
import sqlite3

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