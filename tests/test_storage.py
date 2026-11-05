from logsentry.storage import init_db


def table_names(conn):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    return {row["name"] for row in rows}


def test_init_db_creates_tables():
    conn = init_db(":memory:")
    assert {"events", "alerts"} <= table_names(conn)


def test_init_db_twice_is_safe(tmp_path):
    path = tmp_path / "test.db"
    init_db(path).close()
    conn = init_db(path)    # second time: IF NOT EXISTS means no error
    assert {"events", "alerts"} <= table_names(conn)