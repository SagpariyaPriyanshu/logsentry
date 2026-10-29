"""Parse Linux auth.log lines into Event objects."""
import re
from datetime import datetime

from logsentry.models import Event

# Step 1: every auth.log line starts the same way:
#   Oct  7 14:00:02 web01 sshd[4821]: <message>
HEADER = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "   # timestamp
    r"(?P<host>\S+) "                                 # hostname
    r"(?P<program>[\w-]+)(?:\[\d+\])?: "              # program, optional [pid]
    r"(?P<message>.*)$"                               # everything after
)

# Step 2: what to look for in each program's message.
# Each rule is (program, pattern, event_type). The first match wins.
RULES = [
    ("sshd", re.compile(r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)"),
     "login_failed"),
    ("sshd", re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+)"),
     "login_success"),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<command>.+)$"),
     "sudo"),
    ("useradd", re.compile(r"new user: name=(?P<user>[^,]+)"),
     "user_added"),
    ("usermod", re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"),
     "group_added"),
]


def parse_auth_timestamp(text, year):
    """Turn 'Oct  7 14:00:02' into a datetime. auth.log has no year, so we supply it."""
    return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")


def parse_auth_line(line, year):
    """Turn one auth.log line into an Event, or None if it's not one we care about."""
    header = HEADER.match(line)
    if header is None:
        return None   # not even a valid auth.log line

    for program, pattern, event_type in RULES:
        if header["program"] != program:
            continue   # this rule is for a different program
        match = pattern.search(header["message"])
        if match is None:
            continue   # right program, wrong kind of message

        fields = match.groupdict()          # e.g. {"user": "admin", "ip": "...", ...}
        user = fields.pop("user", None)     # take user and ip out; they get
        ip = fields.pop("ip", None)         # their own boxes on the Event
        if "invalid" in fields:
            fields["invalid_user"] = fields.pop("invalid") is not None

        return Event(
            timestamp=parse_auth_timestamp(header["ts"], year),
            source="auth",
            event_type=event_type,
            raw=line,
            ip=ip,
            user=user,
            details={"host": header["host"], **fields},
        )

    return None   # valid line, but no rule matched (e.g. CRON noise)


def parse_auth_file(path, year=None):
    """Parse a whole auth.log. Returns (events, number_of_skipped_lines)."""
    if year is None:
        year = datetime.now().year

    events = []
    skipped = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            event = parse_auth_line(line, year)
            if event is None:
                skipped += 1
            else:
                events.append(event)
    return events, skipped