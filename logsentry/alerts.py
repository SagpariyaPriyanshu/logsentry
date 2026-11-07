"""Send alerts to Discord."""
import time

import requests

DISCORD_LIMIT = 2000        # Discord rejects messages longer than this
EVIDENCE_LINES = 3          # how many raw log lines to include
MAX_LINE = 300              # cut very long log lines down to this

SEVERITY_ICONS = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def format_alert(alert):
    """Turn an Alert into a short Discord message (Markdown text)."""
    icon = SEVERITY_ICONS.get(alert.severity, "⚪")
    lines = [
        f"{icon} **{alert.severity.upper()}** · `{alert.rule}`",
        alert.message,
        f"**Time:** {alert.timestamp:%Y-%m-%d %H:%M:%S}",
    ]
    if alert.ip:
        lines.append(f"**IP:** `{alert.ip}`")
    if alert.user:
        lines.append(f"**User:** `{alert.user}`")

    if alert.evidence:
        shown = [shorten(line, MAX_LINE) for line in alert.evidence[:EVIDENCE_LINES]]
        lines.append("**Evidence:**")
        lines.append("```")
        lines.extend(shown)
        lines.append("```")
        hidden = len(alert.evidence) - len(shown)
        if hidden > 0:
            lines.append(f"…and {hidden} more lines")

    return shorten("\n".join(lines), DISCORD_LIMIT)


def shorten(text, limit):
    """Cut `text` to at most `limit` characters, ending with … if it was cut."""
    if len(text) <= limit:
        return text
    return text[:limit - 1] + "…"

def send_discord(webhook_url, text, max_retries=2):
    """Post `text` to a Discord webhook. Returns True if Discord accepted it.

    Never raises: a network problem must not crash the whole tool.
    """
    payload = {
        "content": text,
        # Log text comes from attackers. Never let it ping @everyone or anyone else.
        "allowed_mentions": {"parse": []},
    }
    for attempt in range(max_retries + 1):
        try:
            response = requests.post(webhook_url, json=payload, timeout=5)
        except requests.RequestException as error:
            print(f"Discord: could not send ({error.__class__.__name__})")
            return False

        if response.status_code == 429 and attempt < max_retries:
            # Rate limited: Discord tells us how many seconds to wait.
            wait = float(response.json().get("retry_after", 1))
            time.sleep(wait)
            continue

        if response.ok:
            return True
        print(f"Discord: rejected with HTTP {response.status_code}")
        return False
    return False