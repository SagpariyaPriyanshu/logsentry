from logsentry.config import get_discord_webhook, load_env_file

WEBHOOK = "https://discord.com/api/webhooks/123/abc"


def test_load_env_file_sets_variables(tmp_path, monkeypatch):
    monkeypatch.delenv("LOGSENTRY_DISCORD_WEBHOOK", raising=False)
    env = tmp_path / ".env"
    env.write_text(f'# my secrets\nLOGSENTRY_DISCORD_WEBHOOK="{WEBHOOK}"\n')
    load_env_file(env)
    assert get_discord_webhook() == WEBHOOK


def test_real_environment_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGSENTRY_DISCORD_WEBHOOK", "https://already.set")
    env = tmp_path / ".env"
    env.write_text(f"LOGSENTRY_DISCORD_WEBHOOK={WEBHOOK}\n")
    load_env_file(env)
    assert get_discord_webhook() == "https://already.set"


def test_missing_file_and_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("LOGSENTRY_DISCORD_WEBHOOK", raising=False)
    load_env_file(tmp_path / "nope.env")     # no error
    assert get_discord_webhook() is None