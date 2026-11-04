"""Parse Apache/Nginx access log lines (combined log format) into Event objects."""
import re
from datetime import datetime
from urllib.parse import unquote

from logsentry.models import Event

# One combined-log-format line:
#   192.0.2.24 - - [07/Oct/2026:14:00:00 +1100] "GET /products HTTP/1.1" 200 5123 "-" "Mozilla/5.0 ..."
LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) '                 # IP, identity (unused), user
    r'\[(?P<ts>[^\]]+)\] '                             # [timestamp]
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '       # "METHOD /path HTTP/1.1"
    r'(?P<status>\d{3}) (?P<size>\d+|-)'               # status code and size
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'  # referrer and user agent (optional)
)


def parse_web_timestamp(text):
    """Turn '07/Oct/2026:14:00:00 +1100' into a datetime."""
    ts = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
    # Drop the timezone so web times look like auth.log times (local, no zone).
    # Python refuses to compare times with and without a zone.
    return ts.replace(tzinfo=None)


def parse_web_line(line):
    """Turn one access log line into an Event, or None if it doesn't match."""
    match = LINE.match(line)
    if match is None:
        return None

    size = match["size"]
    return Event(
        timestamp=parse_web_timestamp(match["ts"]),
        source="web",
        event_type="http_request",
        raw=line,
        ip=match["ip"],
        user=None if match["user"] == "-" else match["user"],
        details={
            "method": match["method"],
            "path": unquote(match["path"]),          # '%20' -> ' ', so rules can read it
            "status": int(match["status"]),
            "size": 0 if size == "-" else int(size),
            "referrer": match["referrer"],
            "agent": match["agent"] or "",
        },
    )


def parse_web_file(path):
    """Parse a whole access log. Returns (events, number_of_skipped_lines)."""
    events = []
    skipped = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            event = parse_web_line(line)
            if event is None:
                skipped += 1
            else:
                events.append(event)
    return events, skipped