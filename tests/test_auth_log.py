from logsentry.parsers.auth_log import parse_auth_line

YEAR = 2026


def test_failed_login_from_invalid_user():
    line = ("Oct  7 14:00:02 web01 sshd[4821]: Failed password for invalid user admin "
            "from 203.0.113.45 port 52211 ssh2")
    event = parse_auth_line(line, YEAR)
    assert event.event_type == "login_failed"
    assert event.user == "admin"
    assert event.ip == "203.0.113.45"
    assert event.details["invalid_user"] is True


def test_successful_login():
    line = "Oct  7 14:02:10 web01 sshd[5000]: Accepted password for bob from 203.0.113.45 port 50000 ssh2"
    event = parse_auth_line(line, YEAR)
    assert event.event_type == "login_success"
    assert event.user == "bob"
    assert event.timestamp.hour == 14


def test_sudo_command():
    line = ("Oct  7 14:05:10 web01 sudo:    bob : TTY=pts/0 ; PWD=/home/bob ; "
            "USER=root ; COMMAND=/usr/sbin/useradd -m backdoor")
    event = parse_auth_line(line, YEAR)
    assert event.event_type == "sudo"
    assert event.details["command"] == "/usr/sbin/useradd -m backdoor"


def test_unrelated_line_is_skipped():
    line = ("Oct  7 14:10:00 web01 CRON[1234]: pam_unix(cron:session): "
            "session opened for user root(uid=0) by (uid=0)")
    assert parse_auth_line(line, YEAR) is None