"""Generate a realistic fake auth.log with known attacks hidden inside.

Run from the project folder:  python tools/generate_sample_logs.py
Output: sample_logs/auth.log
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "web01"
USERS = ["alice", "bob", "charlie"]
OFFICE_IPS = ["10.0.0.11", "10.0.0.12", "10.0.0.13"]   # each user's normal IP
VALID_ACCOUNTS = USERS + ["root"]
GUESSED_NAMES = ["root", "admin", "test", "oracle", "ubuntu", "bob"]
ATTACKER_IP = "203.0.113.45"   # 203.0.113.x is reserved for examples, so it's safe
START = datetime(2026, 10, 5)  # a Monday
DAYS = 14


def fmt(ts):
    """Format a time the way auth.log does: 'Oct  5 09:14:02'."""
    return ts.strftime("%b ") + f"{ts.day:>2}" + ts.strftime(" %H:%M:%S")


def pid():
    return random.randint(1000, 9999)


def failed(ts, user, ip):
    who = user if user in VALID_ACCOUNTS else f"invalid user {user}"
    port = random.randint(40000, 65000)
    return f"{fmt(ts)} {HOST} sshd[{pid()}]: Failed password for {who} from {ip} port {port} ssh2"


def accepted(ts, user, ip):
    port = random.randint(40000, 65000)
    return f"{fmt(ts)} {HOST} sshd[{pid()}]: Accepted password for {user} from {ip} port {port} ssh2"


def sudo(ts, user, command):
    return (f"{fmt(ts)} {HOST} sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; "
            f"USER=root ; COMMAND={command}")


def normal_day(day):
    """One day of ordinary activity. Returns a list of (time, line) pairs."""
    lines = []

    # Background noise every 10 minutes. The parser should skip these.
    for minute in range(0, 24 * 60, 10):
        ts = day + timedelta(minutes=minute)
        lines.append((ts, f"{fmt(ts)} {HOST} CRON[{pid()}]: pam_unix(cron:session): "
                          f"session opened for user root(uid=0) by (uid=0)"))

    if day.weekday() >= 5:   # Saturday=5, Sunday=6: nobody logs in
        return lines

    for user, ip in zip(USERS, OFFICE_IPS):
        ts = day + timedelta(hours=random.randint(8, 9), minutes=random.randint(0, 59),
                             seconds=random.randint(0, 59))
        if random.random() < 0.15:   # 15% chance of one password typo first
            lines.append((ts, failed(ts, user, ip)))
            ts += timedelta(seconds=random.randint(5, 20))
        lines.append((ts, accepted(ts, user, ip)))

        if user == "alice" and random.random() < 0.5:   # Alice is the real admin
            ts += timedelta(minutes=random.randint(5, 120))
            lines.append((ts, sudo(ts, "alice", "/usr/bin/apt update")))
    return lines


def inject_attacks():
    """The attacks we hide in the log. This is our answer key."""
    lines = []

    # Attack 1: brute force on Wed 7 Oct, ending in a correct guess for bob
    ts = datetime(2026, 10, 7, 14, 0, 0)
    for _ in range(40):
        lines.append((ts, failed(ts, random.choice(GUESSED_NAMES), ATTACKER_IP)))
        ts += timedelta(seconds=random.randint(2, 4))
    lines.append((ts, accepted(ts, "bob", ATTACKER_IP)))

    # Attack 2: as bob, create a hidden admin account
    ts += timedelta(minutes=3)
    lines.append((ts, sudo(ts, "bob", "/usr/sbin/useradd -m backdoor")))
    ts += timedelta(seconds=1)
    lines.append((ts, f"{fmt(ts)} {HOST} useradd[{pid()}]: new user: name=backdoor, "
                      f"UID=1004, GID=1004, home=/home/backdoor, shell=/bin/bash"))
    ts += timedelta(seconds=20)
    lines.append((ts, sudo(ts, "bob", "/usr/sbin/usermod -aG sudo backdoor")))
    ts += timedelta(seconds=1)
    lines.append((ts, f"{fmt(ts)} {HOST} usermod[{pid()}]: add 'backdoor' to group 'sudo'"))

    # Attack 3: charlie logs in at 3 a.m. on Fri 9 Oct
    ts = datetime(2026, 10, 9, 3, 12, 45)
    lines.append((ts, accepted(ts, "charlie", OFFICE_IPS[2])))
    return lines


# def main():
#     random.seed(42)   # same "random" output every run, so results are repeatable

#     lines = []
#     for d in range(DAYS):
#         lines += normal_day(START + timedelta(days=d))
#     lines += inject_attacks()
#     lines.sort(key=lambda pair: pair[0])   # real logs are in time order

#     out = Path("sample_logs/auth.log")
#     out.parent.mkdir(exist_ok=True)
#     text = "\n".join(line for _, line in lines) + "\n"
#     out.write_text(text, encoding="utf-8", newline="\n")

#     print(f"Wrote {len(lines)} lines to {out}")
#     print("Hidden attacks (answer key):")
#     print("  1. Brute force: 40 failures from 203.0.113.45 on 7 Oct ~14:00, then bob logs in")
#     print("  2. Privilege escalation: 'backdoor' user created and added to sudo by bob")
#     print("  3. Unusual login: charlie at 03:12 on 9 Oct")

# ---------------------------------------------------------------------------
# Web server access log (Apache/Nginx "combined" format)
# ---------------------------------------------------------------------------

VISITOR_IPS = [f"192.0.2.{n}" for n in range(10, 60)]   # 192.0.2.x is another example range
SCANNER_IP = "198.51.100.23"
SQLMAP_IP = "198.51.100.77"

NORMAL_PAGES = ["/", "/index.html", "/about", "/contact", "/products",
                "/products.php?id=3", "/products.php?id=7", "/blog",
                "/css/style.css", "/js/app.js", "/images/logo.png"]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
SCAN_PATHS = ["/wp-admin", "/wp-login.php", "/.env", "/.git/config", "/phpmyadmin",
              "/admin", "/backup.zip", "/config.php", "/server-status", "/cgi-bin/test.cgi",
              "/../../etc/passwd", "/shell.php", "/db.sql", "/old", "/test"]


def web_fmt(ts):
    """Format a time the way access logs do: '07/Oct/2026:14:00:00 +1100'."""
    return ts.strftime("%d/%b/%Y:%H:%M:%S") + " +1100"


def web_line(ts, ip, method, path, status, size, agent):
    """One line in combined log format."""
    return (f'{ip} - - [{web_fmt(ts)}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "-" "{agent}"')


def normal_web_day(day):
    """One day of ordinary website visitors. Returns (time, line) pairs."""
    lines = []
    visits = random.randint(120, 200)
    for _ in range(visits):
        ts = day + timedelta(hours=random.randint(7, 22), minutes=random.randint(0, 59),
                             seconds=random.randint(0, 59))
        ip = random.choice(VISITOR_IPS)
        if random.random() < 0.03:   # 3% of requests hit a page that doesn't exist
            lines.append((ts, web_line(ts, ip, "GET", "/favicon.ico", 404, 196,
                                       random.choice(BROWSERS))))
        else:
            lines.append((ts, web_line(ts, ip, "GET", random.choice(NORMAL_PAGES), 200,
                                       random.randint(800, 12000), random.choice(BROWSERS))))
    return lines


def inject_web_attacks():
    """Web attacks hidden in access.log. This is the web answer key."""
    lines = []

    # Attack 4: Nikto scanner on Thu 8 Oct at 22:30, probing for weak spots
    ts = datetime(2026, 10, 8, 22, 30, 0)
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000123)"
    for i in range(60):
        path = SCAN_PATHS[i % len(SCAN_PATHS)]
        lines.append((ts, web_line(ts, SCANNER_IP, "GET", path, 404, 196, nikto)))
        ts += timedelta(seconds=random.randint(1, 3))

    # Attack 5: sqlmap testing the products page for SQL injection on Sat 10 Oct
    ts = datetime(2026, 10, 10, 2, 5, 0)
    sqlmap = "sqlmap/1.8.11#stable (https://sqlmap.org)"
    payloads = ["3'", "3' OR 1=1--", "3 AND 1=1", "3 AND 1=2", "3 UNION SELECT NULL--",
                "3 UNION SELECT NULL,NULL--", "3' AND SLEEP(5)--", "3; DROP TABLE users--"]
    for payload in payloads:
        path = "/products.php?id=" + payload.replace(" ", "%20")
        lines.append((ts, web_line(ts, SQLMAP_IP, "GET", path, 500, 312, sqlmap)))
        ts += timedelta(seconds=random.randint(1, 2))
    return lines


def write_log(path, lines):
    """Sort (time, line) pairs by time and write them as a Linux-style log file."""
    lines.sort(key=lambda pair: pair[0])
    out = Path(path)
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(line for _, line in lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {len(lines):,} lines to {out}")

def main():
    random.seed(42)   # same "random" output every run, so results are repeatable

    auth_lines = []
    for d in range(DAYS):
        auth_lines += normal_day(START + timedelta(days=d))
    auth_lines += inject_attacks()
    write_log("sample_logs/auth.log", auth_lines)

    web_lines = []
    for d in range(DAYS):
        web_lines += normal_web_day(START + timedelta(days=d))
    web_lines += inject_web_attacks()
    write_log("sample_logs/access.log", web_lines)

    print("Hidden attacks (answer key):")
    print("  1. Brute force: 40 failures from 203.0.113.45 on 7 Oct ~14:00, then bob logs in")
    print("  2. Privilege escalation: 'backdoor' user created and added to sudo by bob")
    print("  3. Unusual login: charlie at 03:12 on 9 Oct")
    print("  4. Web scan: Nikto from 198.51.100.23 on 8 Oct ~22:30, 60 requests, all 404")
    print("  5. SQL injection: sqlmap from 198.51.100.77 on 10 Oct ~02:05, 8 requests")

if __name__ == "__main__":
    main()