"""Load LogSentry settings from config.yaml, filling gaps with defaults."""
import copy
import os
from pathlib import Path

import yaml

# Used for any setting missing from config.yaml, so a detector never
# crashes because someone deleted a line.
DEFAULTS = {
    "brute_force": {"max_failures": 5, "window_minutes": 2},
    "unusual_login": {"work_hours": [7, 19], "learning_days": 3},
    "privilege": {"sudo_allowlist": []},
    "web_scan": {
        "max_404s": 20,
        "window_minutes": 5,
        "bad_paths": ["/wp-admin", "/.env", "/.git", "../", "' OR 1=1", "UNION SELECT"],
        "bad_agents": ["sqlmap", "nikto"],
    },
    "alerting": {"min_severity": "high"},
    "database": {"path": "logsentry.db"},
}


def merge(defaults, overrides):
    """Return a copy of defaults with overrides laid on top, section by section."""
    result = copy.deepcopy(defaults)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)   # merge inside the section
        else:
            result[key] = value                        # plain value: replace it
    return result


def load_config(path="config.yaml"):
    """Read config.yaml and return the full settings as a dictionary."""
    path = Path(path)
    if not path.exists():
        return copy.deepcopy(DEFAULTS)

    with open(path, encoding="utf-8") as f:
        user_settings = yaml.safe_load(f) or {}   # an empty file gives None

    return merge(DEFAULTS, user_settings)

# discord webhook configuration 
def load_env_file(path=".env"):
    """Copy KEY=value lines from a .env file into environment variables.

    Secrets live in .env, which Git ignores, so they never reach GitHub.
    A variable that is already set is left alone, so a real environment wins.
    """
    path = Path(path)
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue                      # skip blanks, comments and junk
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_discord_webhook():
    """Return the Discord webhook URL, or None if it isn't configured."""
    return os.environ.get("LOGSENTRY_DISCORD_WEBHOOK") or None