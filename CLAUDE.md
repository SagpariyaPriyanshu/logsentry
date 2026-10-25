# LogSentry: Mini SIEM (Project 1)

Python log analyzer and intrusion alert tool, built as a cyber security resume project
(SOC / analyst roles). Full plan, module reference and roadmap: `docs/DEVELOPMENT_GUIDE.md`.
Read it before starting any phase.

## How we work: learning mode

The owner (Priyansuh) is learning while building. Optimise for understanding, not speed.

- Build ONE function or small step at a time. Never write a whole module in one go.
- Before writing code: explain in plain words what the function does, its inputs and
  outputs, and any new concept it uses (regex, dataclass, sliding window, SQL, etc.).
- After writing code: walk through it line by line for anything non-obvious, then show
  how to run or test it.
- Prefer clear, readable code over clever code. Comment the "why", not the "what".
- Ask before adding a dependency, changing the folder structure, or skipping ahead a phase.
- End each step by suggesting a Git commit message.
- When a phase milestone is reached, tick its boxes in `docs/DEVELOPMENT_GUIDE.md`
  and update "Current status" below.

## Tech stack

Python 3.11+, `re`, `dataclasses`, `sqlite3`, pandas, Streamlit + Plotly, PyYAML,
requests, pytest. Dashboard is Streamlit (Flask is a later upgrade only).

## Structure (target)

```
main.py                     CLI: analyze / watch
config.yaml                 thresholds, paths, webhook (secrets via env vars)
logsentry/models.py         Event, Alert dataclasses
logsentry/config.py         load_config()
logsentry/parsers/          auth_log.py, web_log.py  -> list[Event]
logsentry/detectors/        brute_force, unusual_login, privilege, web_scan
                            each: detect_x(events, cfg) -> list[Alert]
logsentry/storage.py        SQLite (parameterised queries only)
logsentry/alerts.py         Discord webhook / email
logsentry/enrich.py         AbuseIPDB (bonus)
logsentry/tail.py           live mode (stretch)
dashboard/app.py            Streamlit dashboard
tools/generate_sample_logs.py  fake logs with known injected attacks
tests/                      pytest
```

## Rules

- Never commit secrets. Webhook URLs and API keys come from environment variables or an
  untracked `.env`; keep `.env`, `*.db` and `.venv/` in `.gitignore`.
- All SQL uses `?` placeholders.
- Every detector has a pytest test with an "should alert" and a "should not alert" case.
- Home-lab attacks only against VMs the owner controls, on an isolated network.

## Commands

- Run: `python main.py analyze sample_logs/auth.log`
- Tests: `pytest -q`
- Dashboard: `streamlit run dashboard/app.py`

## Current status

Phase 0 (setup) not started. OS: not yet confirmed (ask on first session).
