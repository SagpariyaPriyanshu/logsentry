# Project 1: Mini SIEM Development Guide

## What we're building

We are building **LogSentry**, a mini SIEM in Python. It reads security logs, turns each line into a structured event, runs detection rules, raises alerts, and shows everything on a web dashboard. It is built in phases, and each phase ends with something that runs.

**The finished tool will:**

- Parse Linux `auth.log` (SSH logins, `sudo`, user changes) and web server access logs (Apache/Nginx format)
- Detect 4 threat types: brute-force logins, unusual logins, privilege escalation, and web scanning
- Store events and alerts in a SQLite database
- Send alerts to Discord (webhook) and optionally email
- Show a Streamlit dashboard: top attacking IPs, failed logins over time, alert list
- Bonus: check attacker IPs against AbuseIPDB

**Assumptions:**

- You know basic Python (variables, loops, functions). Everything beyond that is explained as we build it.
- It runs on Windows, macOS or Linux, because it reads log *files*. A sample log generator means you don't need a Linux server to start.
- Streamlit for the dashboard, because it needs no HTML or JavaScript. Flask is listed as an upgrade path.
- Windows Event Logs come in a stretch phase, after the core works.

**What you'll learn:** regular expressions, dataclasses, file parsing, sliding-window detection logic, SQL with SQLite, pandas, REST APIs and webhooks, config files, unit testing with pytest, and how a real SOC pipeline fits together.

## Architecture

Each log line moves left to right: parsed into an Event, checked by the detectors, then stored and, if serious, sent to Discord.

```
                                 config.yaml
                                 (thresholds)
                                      |
                                      v
 Log files  ---->  Parsers  --Events-->  Detectors  --Alerts-->  Notifier
 auth.log          regex ->              4 rules,                Discord / email
 access.log        Events                sliding window
                      |                      |
                      | save events          | save alerts
                      v                      v
 AbuseIPDB  --scores-->        SQLite (events + alerts)  --reads-->  Dashboard
 (bonus)                                                             Streamlit
```

The dashboard only reads from the database, so detection and display stay independent. That separation is how real SIEMs are built too.

## Folder structure and setup

Every file below gets built during the project. Each folder has one job, so you always know where code belongs.

```
logsentry/
├── README.md                 # what it does, screenshots, how to run
├── CLAUDE.md                 # project context for Claude Code
├── requirements.txt          # Python packages
├── config.yaml               # thresholds, webhook URL, file paths
├── main.py                   # command-line entry point
├── docs/
│   └── DEVELOPMENT_GUIDE.md  # this file
├── logsentry/
│   ├── __init__.py
│   ├── models.py             # Event and Alert data shapes
│   ├── config.py             # loads config.yaml
│   ├── parsers/
│   │   ├── auth_log.py       # Linux auth.log -> Events
│   │   └── web_log.py        # Apache/Nginx access log -> Events
│   ├── detectors/
│   │   ├── __init__.py       # runs every detector
│   │   ├── brute_force.py
│   │   ├── unusual_login.py
│   │   ├── privilege.py
│   │   └── web_scan.py
│   ├── storage.py            # SQLite read/write
│   ├── alerts.py             # Discord / email notifications
│   ├── enrich.py             # AbuseIPDB lookups (bonus)
│   └── tail.py               # live monitoring (stretch)
├── dashboard/
│   └── app.py                # Streamlit dashboard
├── tools/
│   └── generate_sample_logs.py  # fake logs with attacks mixed in
├── sample_logs/              # generated test data
└── tests/                    # pytest unit tests
```

**Setup (Phase 0, about 30 minutes):**

1. Install Python 3.11 or newer, VS Code, and Git.
2. Create the folder and a virtual environment: `python -m venv .venv`, then activate it (`.venv\Scripts\activate` on Windows, `source .venv/bin/activate` on macOS/Linux).
3. Install packages: `pip install pandas streamlit plotly pyyaml requests pytest`.
4. Run `git init` and make a GitHub repo now, so every phase becomes a commit employers can see.

| Package | Why we need it |
| --- | --- |
| `re`, `sqlite3`, `dataclasses` | Built into Python: regex parsing, database, data shapes |
| pandas | Grouping and counting events for detection and charts |
| streamlit + plotly | The dashboard and its charts |
| pyyaml | Reading `config.yaml` |
| requests | Calling the Discord webhook and AbuseIPDB API |
| pytest | Automated tests |

## Module guide: every file and function

### models.py: the shared data shapes

Every part of the tool speaks the same language: an **Event** (one thing that happened) and an **Alert** (something suspicious). Using `@dataclass` gives us clean objects instead of loose dictionaries.

```python
@dataclass
class Event:
    timestamp: datetime
    source: str        # "auth" or "web"
    event_type: str    # "login_failed", "login_success", "sudo", "user_added", "http_request"
    ip: str | None
    user: str | None
    details: dict      # extra fields, e.g. {"status": 404, "path": "/wp-admin"}
    raw: str           # the original log line, kept as evidence

@dataclass
class Alert:
    timestamp: datetime
    rule: str          # "brute_force", "web_scan", ...
    severity: str      # "low", "medium", "high"
    ip: str | None
    user: str | None
    message: str       # human-readable summary
    evidence: list[str]  # the raw lines that triggered it
```

### config.py: settings in one place

| Function | In → Out | How it works |
| --- | --- | --- |
| `load_config(path)` | file path → dict | Opens `config.yaml` with `yaml.safe_load`, fills in defaults for anything missing, and returns the settings. Detectors read thresholds from here, so you tune rules without touching code. |

Example config values: `brute_force.max_failures: 5`, `brute_force.window_minutes: 2`, `work_hours: [7, 19]`, `web_scan.max_404s: 20`, `discord_webhook_url` (read from an environment variable).

### parsers/auth_log.py: reading Linux login logs

A real `auth.log` line looks like this:

```
Oct 11 23:14:02 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 52211 ssh2
```

| Function | In → Out | How it works |
| --- | --- | --- |
| `parse_auth_line(line, year)` | one text line → `Event` or `None` | Tries a list of compiled regex patterns in turn: failed password, accepted password/key, `sudo` command, `useradd`, `usermod -aG sudo`. The first match pulls out the timestamp, user and IP with named groups. No match returns `None`, so unrelated lines are skipped. |
| `parse_auth_timestamp(text, year)` | `"Oct 11 23:14:02"` → `datetime` | auth.log omits the year, so we pass it in and use `datetime.strptime`. |
| `parse_auth_file(path)` | file path → list of `Event` | Opens the file, loops line by line (memory-friendly for huge logs), calls `parse_auth_line` on each, and counts lines it could not parse for a summary. |

The key regex, explained:

```python
FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+ [\d:]{8}) \S+ sshd\[\d+\]: "
    r"Failed password for (invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)
# (?P<name>...) = a named group we can read later with match["name"]
# \S+ = one word with no spaces; [\d.]+ = digits and dots (an IPv4 address)
```

### parsers/web_log.py: reading web server logs

A combined-format access log line:

```
198.51.100.7 - - [11/Oct/2026:23:20:11 +1100] "GET /wp-admin HTTP/1.1" 404 162 "-" "sqlmap/1.7"
```

| Function | In → Out | How it works |
| --- | --- | --- |
| `parse_web_line(line)` | one line → `Event` or `None` | One regex captures IP, timestamp, method, path, status code, size and user agent. Stored as `event_type="http_request"` with the rest in `details`. |
| `parse_web_file(path)` | file path → list of `Event` | Same pattern as the auth parser. |

### detectors/: the detection rules

Every detector has the same shape: it takes the list of events and the config, and returns a list of alerts. That shared shape is what lets `run_all_detectors` treat them all the same way.

| Function | Rule | How it works |
| --- | --- | --- |
| `detect_brute_force(events, cfg)` | 5+ failed logins from one IP within 2 minutes → **high** | Filters to `login_failed`, groups by IP, sorts by time, then slides a window (see below). Raises one alert per burst, not per line, to avoid alert floods. Escalates if a success from the same IP follows the failures, since that may mean the attacker got in. |
| `detect_unusual_login(events, cfg)` | Successful login outside work hours, or from an IP that user has never used → **medium** | Walks successful logins in time order, keeping a `dict` of user → set of known IPs. A first-ever IP after a learning period, or an hour outside `work_hours`, raises an alert. |
| `detect_privilege_escalation(events, cfg)` | New user created, user added to `sudo`/`admin`, or `sudo` by a non-allowlisted user → **high** | Simple matching on `event_type` and `details`. An allowlist in config (e.g. your own admin account) cuts false positives. |
| `detect_web_scan(events, cfg)` | 20+ 404s from one IP in 5 minutes, or requests for known attack paths (`/wp-admin`, `/.env`, `../`, `' OR 1=1`) or scanner user agents (`sqlmap`, `nikto`) → **medium** | Window counting like brute force, plus a list of suspicious substrings checked against the path and user agent. |
| `run_all_detectors(events, cfg)` | n/a | Calls each detector in a list, joins the results, and sorts alerts by time. Adding a new rule later means writing one function and adding it to the list. |

The sliding window is the most important idea in the project:

```python
def find_bursts(times, max_count, window):
    """times: sorted datetimes of failures from ONE IP."""
    start = 0
    for end in range(len(times)):
        # shrink the window from the left until it spans <= `window`
        while times[end] - times[start] > window:
            start += 1
        if end - start + 1 >= max_count:
            yield times[start], times[end]
```

Two pointers move forward through the list once, so it stays fast even with 100,000 events.

### storage.py: the SQLite database

| Function | In → Out | How it works |
| --- | --- | --- |
| `init_db(path)` | db path → connection | Creates `events` and `alerts` tables if they don't exist, plus indexes on `ip` and `timestamp` for fast dashboard queries. |
| `save_events(conn, events)` | events → count saved | `executemany` with `?` placeholders. Placeholders matter: they prevent SQL injection, which is a good interview point. |
| `save_alerts(conn, alerts)` | alerts → count saved | Same, storing `evidence` as JSON text. |
| `load_events_df(conn, since)` | time → pandas DataFrame | `pd.read_sql` straight into a DataFrame for the dashboard. |
| `load_alerts_df(conn, since)` | time → DataFrame | Same for alerts. |
| `already_alerted(conn, rule, ip, window)` | → True/False | Checks whether this rule already fired for this IP recently, so re-running the tool doesn't repeat alerts (deduplication). |

### alerts.py: notifications

| Function | In → Out | How it works |
| --- | --- | --- |
| `format_alert(alert)` | `Alert` → text | Builds a readable message: severity, rule, IP, user, time, and the first 3 evidence lines. |
| `send_discord(alert, url)` | → True/False | `requests.post` to the webhook with a JSON body; Discord shows it as a message. Has a timeout and catches errors so a network failure never crashes detection. |
| `send_email(alert, smtp_cfg)` | → True/False | Optional. Uses Python's `smtplib` with a Gmail app password. |
| `dispatch(alerts, cfg)` | alerts → count sent | Sends only alerts at or above `min_severity` from config, so low-level noise stays on the dashboard. |

### enrich.py: IP reputation (bonus)

| Function | In → Out | How it works |
| --- | --- | --- |
| `check_ip_reputation(ip, api_key)` | IP → dict | Calls AbuseIPDB's check endpoint and returns the abuse score, country and ISP. Private IPs (`10.x`, `192.168.x`) are skipped using Python's `ipaddress` module. |
| `get_cached_reputation(conn, ip)` | IP → dict or None | Looks in a cache table first, because the free tier has a daily request limit. |

### dashboard/app.py: the Streamlit dashboard

| Part | What it shows | How it works |
| --- | --- | --- |
| Sidebar filters | Time range, severity, source | `st.sidebar.selectbox`; every chart re-filters when you change one. |
| Metric cards | Total events, failed logins, alerts, unique attacker IPs | `st.metric` from simple DataFrame counts. |
| Failed logins over time | Line chart | `df.resample("10min").size()` then `plotly.express.line`. |
| Top attacking IPs | Bar chart, top 10 | `value_counts().head(10)`. |
| Alerts table | Every alert, newest first, colour by severity | `st.dataframe`; click a row to see its evidence lines. |

Run it with `streamlit run dashboard/app.py`; it opens in your browser.

### main.py: the command line

| Command | What it does |
| --- | --- |
| `python main.py analyze sample_logs/auth.log` | Parse → store → detect → alert, then print a summary |
| `python main.py analyze --web sample_logs/access.log` | Same for a web log |
| `python main.py watch /var/log/auth.log` | Live mode: follows the file as new lines arrive (stretch) |

Built with `argparse`. The `analyze` function is the whole pipeline in about 10 lines, calling the modules above in order.

### tools/generate_sample_logs.py: test data

| Function | How it works |
| --- | --- |
| `generate_auth_log(n, attacks)` | Writes realistic normal traffic (logins in work hours, a few typos), then injects known attacks at known times: a 40-attempt brute force, a 3 a.m. login, a new sudo user. Because we know exactly what was injected, we can check the detector catches all of it and nothing else. |
| `generate_web_log(n, attacks)` | Normal page views plus a scanner burst of 404s and `sqlmap` requests. |

### tail.py: live monitoring (stretch)

| Function | How it works |
| --- | --- |
| `follow(path)` | Opens the file, jumps to the end, and loops: read a new line if there is one, otherwise sleep 1 second. Yields lines as they're written, like `tail -f`. Each line is parsed and run through the detectors immediately. |

## Development roadmap

We build in 7 phases, about 3–4 weeks at a few hours a week. Each phase ends with working code and a Git commit, and we learn each concept right before we use it. Tick the boxes as we go.

### Phase 0: Setup

**You learn:** virtual environments, Git basics, project layout.

- [ ] Install Python, VS Code, Git; create the repo and virtual environment
- [ ] Create the folder structure and `requirements.txt`
- [ ] First commit and push to GitHub

### Phase 1: Sample data and parsing

**You learn:** regex, dataclasses, reading files, datetime handling.

- [ ] Write `models.py` (Event, Alert)
- [ ] Build `generate_sample_logs.py` and create sample `auth.log` and `access.log`
- [ ] Build `parse_auth_line` and `parse_auth_file`
- [ ] Build `parse_web_line` and `parse_web_file`
- [ ] **Milestone:** `python main.py analyze` prints "Parsed 5,000 events, 12 lines skipped"

### Phase 2: Detection rules

**You learn:** grouping, sorting, the sliding-window algorithm, config files, false positives.

- [ ] Write `config.yaml` and `load_config`
- [ ] Build `detect_brute_force` with the sliding window
- [ ] Build `detect_unusual_login`, `detect_privilege_escalation`, `detect_web_scan`
- [ ] Build `run_all_detectors`
- [ ] **Milestone:** every attack injected by the generator is caught, and normal traffic raises no alerts

### Phase 3: Storage

**You learn:** SQL basics, SQLite, parameterised queries (and why they stop SQL injection), deduplication.

- [ ] Build `storage.py`: `init_db`, `save_events`, `save_alerts`, `already_alerted`
- [ ] Connect it into `main.py`
- [ ] **Milestone:** running the tool twice does not create duplicate alerts

### Phase 4: Alerting

**You learn:** HTTP requests, JSON, webhooks, handling network errors, keeping secrets out of Git.

- [ ] Create a private Discord server and webhook
- [ ] Build `format_alert`, `send_discord`, `dispatch`
- [ ] Store the webhook URL in an environment variable or untracked file, never in the repo
- [ ] **Milestone:** a brute-force attack in the sample log shows up as a Discord message

### Phase 5: Dashboard

**You learn:** Streamlit, pandas time series, Plotly charts.

- [ ] Build metric cards, failed-logins chart, top-IPs chart, alerts table, filters
- [ ] **Milestone:** a dashboard screenshot good enough for your README

### Phase 6: Bonus and polish

**You learn:** external APIs, rate limits and caching, live file monitoring, writing for GitHub.

- [ ] AbuseIPDB enrichment with caching (`enrich.py`)
- [ ] Live `watch` mode (`tail.py`)
- [ ] Optional: Windows Event Log support (failed logon event 4625, successful logon 4624)
- [ ] Write the README with screenshots and a demo GIF
- [ ] **Milestone:** project is public, documented, and on your resume

Upgrade path once it all works: swap Streamlit for Flask, add Docker, or forward logs from a VM in your home lab.

## Testing and home lab

We test in three layers: unit tests for each function, a full run on generated data with known attacks, and a real attack in a home lab.

| Layer | What we check | Example |
| --- | --- | --- |
| Unit tests (`tests/`, pytest) | Each parser and detector on tiny hand-written inputs | 4 failures in 2 minutes → no alert; 5 → one alert; 5 spread over 10 minutes → no alert |
| Generated data | The whole pipeline on 50,000+ lines | Every injected attack caught, zero alerts on clean traffic; we record the numbers for the resume |
| Home lab | Real logs from a real attack | Ubuntu VM in VirtualBox with SSH on; a Kali VM runs `hydra` against it; LogSentry reads the Ubuntu `/var/log/auth.log` |

The home lab only ever attacks machines you own, on an isolated VirtualBox network. Attacking systems without permission is illegal in Australia, and that boundary is worth stating in interviews too.

We'll also note false positives as we tune: a user mistyping their password 5 times is a real false positive, and how you handle it (allowlists, higher thresholds, lower severity) is a classic interview question.

## Resume, GitHub and interviews

**Resume bullet (fill in real numbers at the end):** Built LogSentry, a Python mini SIEM that parses Linux and web server logs, detects brute-force, privilege-escalation and scanning activity with configurable rules, and sends real-time Discord alerts; tested against 50,000+ log entries and a live home-lab attack.

**Interview talking points this project gives you:**

- How a SIEM pipeline works: collect, parse, normalise, detect, alert, visualise
- How the sliding-window rule works and why thresholds are configurable
- False positives versus false negatives, and how you tuned the rules
- Why parameterised SQL queries prevent injection
- Which log sources matter and what attackers leave behind in them
- How you'd scale it: a real SIEM such as Splunk, Microsoft Sentinel or Elastic does the same job at enterprise size
