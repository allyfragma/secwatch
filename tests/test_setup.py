import os
import stat

import httpx

from secwatch import doctor, envfile
from secwatch.config import Settings
from secwatch.setup_wizard import Io, detect_logs, detect_timezone, run_setup, telegram_wait_for_chat

TOKEN = "fake-bot-token-for-tests"  # not token-shaped on purpose: secret scanners flag look-alikes


def test_env_update_keeps_comments_order_and_unrelated_keys(tmp_path):
    path = tmp_path / "secwatch.env"
    path.write_text("# comment\nSECWATCH_WEB_USER=admin\nSECWATCH_TIMEZONE=UTC\nOTHER='x y'\n")
    envfile.update_env(str(path), {"SECWATCH_TIMEZONE": "Europe/Berlin", "SECWATCH_LANG": "ru", "OTHER": None})
    assert path.read_text() == "# comment\nSECWATCH_WEB_USER=admin\nSECWATCH_TIMEZONE=Europe/Berlin\nSECWATCH_LANG=ru\n"
    assert stat.S_IMODE(os.stat(path).st_mode) & 0o007 == 0  # never world-readable
    assert envfile.read_env(str(path))["SECWATCH_LANG"] == "ru"


def test_env_rejects_multiline_values(tmp_path):
    try:
        envfile.update_env(str(tmp_path / "e"), {"SECWATCH_X": "a\nSECWATCH_WEB_PASSWORD="})
    except ValueError:
        return
    raise AssertionError("newline injection must be refused")


def test_detect_logs_and_timezone(tmp_path):
    for rel in ("var/log/auth.log", "var/log/fail2ban.log", "var/log/caddy/site/access.json",
                "var/log/caddy/site/access-2026-10-20T08-07-28.700-time.json", "etc/timezone"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("Europe/Lisbon\n" if rel == "etc/timezone" else "")
    found = detect_logs(str(tmp_path))
    assert found["SECWATCH_AUTH_LOGS"] == ["/var/log/auth.log"]
    assert found["SECWATCH_CADDY_LOGS"] == ["/var/log/caddy/site/access.json"]  # rotated copy skipped
    assert found["SECWATCH_NGINX_LOGS"] == []
    assert detect_timezone(str(tmp_path)) == "Europe/Lisbon"


def telegram_and_supabase(calls):
    def handler(request: httpx.Request):
        url = str(request.url)
        calls.append(url.split("/bot")[0] + ("/bot<token>/" + url.rsplit("/", 1)[1] if "/bot" in url else ""))
        if url.endswith("/getMe"):
            ok = TOKEN in url
            return httpx.Response(200 if ok else 401, json={"ok": ok, "result": {"username": "alerts_bot"}} if ok else {"ok": False})
        if url.endswith("/getUpdates"):
            return httpx.Response(200, json={"ok": True, "result": [
                {"message": {"chat": {"id": 42, "first_name": "Ann"}}}]})
        if url.endswith("/sendMessage"):
            return httpx.Response(200, json={"ok": True})
        if "/advisors/security" in url:
            good = request.headers["authorization"] == "Bearer sbp_good"
            return httpx.Response(200 if good else 401, json={"lints": []})
        raise AssertionError(url)
    return httpx.Client(transport=httpx.MockTransport(handler))


def scripted(answers, secrets, said):
    a, s = iter(answers), iter(secrets)
    return Io(ask=lambda _p: next(a), ask_secret=lambda _p: next(s), say=said.append)


def test_setup_wizard_end_to_end(tmp_path):
    (tmp_path / "var/log").mkdir(parents=True)
    (tmp_path / "var/log/auth.log").write_text("")
    env = tmp_path / "secwatch.env"
    said, calls = [], []
    io = scripted(
        answers=["ru", "", "y", "y", "abcdefghijklmnop"],  # lang, timezone (default), telegram, supabase, ref
        secrets=["wrong", TOKEN, "sbp_good"],               # first token is rejected, second works
        said=said)
    run_setup(str(env), root=str(tmp_path), io=io, client=telegram_and_supabase(calls))
    values = envfile.read_env(str(env))
    assert values["SECWATCH_LANG"] == "ru"
    assert values["SECWATCH_AUTH_LOGS"] == f"{tmp_path}/var/log/auth.log"  # as the monitor sees it
    assert values["SECWATCH_TELEGRAM_TOKEN"] == TOKEN and values["SECWATCH_TELEGRAM_CHAT_ID"] == "42"
    assert values["SECWATCH_SUPABASE_PROJECT_REF"] == "abcdefghijklmnop" and values["SECWATCH_SUPABASE_TOKEN"] == "sbp_good"
    assert len(values["SECWATCH_WEB_PASSWORD"]) >= 24
    printed = "\n".join(said)
    for secret in (TOKEN, "sbp_good", values["SECWATCH_WEB_PASSWORD"]):
        assert secret not in printed  # secrets are never echoed
    assert "Telegram rejected the token" in printed and "Chat: Ann" in printed


def test_setup_keeps_existing_password(tmp_path):
    env = tmp_path / "secwatch.env"
    env.write_text("SECWATCH_WEB_PASSWORD=keep-me\n")
    run_setup(str(env), root=str(tmp_path), io=scripted(["en", "UTC", "n", "n"], [], []),
              client=telegram_and_supabase([]))
    assert envfile.read_env(str(env))["SECWATCH_WEB_PASSWORD"] == "keep-me"


def test_wait_for_chat_explains_webhook_conflict():
    client = httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(409, json={"ok": False, "error_code": 409})))
    try:
        telegram_wait_for_chat(client, TOKEN, timeout=0)
    except Exception as exc:
        assert "webhook" in str(exc)
        return
    raise AssertionError("expected a clear error")


def test_doctor_reports_problems_without_secrets(settings, tmp_path):
    settings.telegram_token, settings.telegram_chat_id = TOKEN, ""
    settings.supabase_token, settings.supabase_project_ref = "sbp_bad", "ref"
    settings.nginx_logs = [str(tmp_path / "missing.log")]
    checks = doctor.run_checks(settings, telegram_and_supabase([]))
    by = {c.name: c for c in checks}
    assert by["database"].status == "ok"
    assert by["SSH log"].status == "ok"
    assert by["nginx log"].status == "warn"
    assert by["Telegram"].status == "fail" and by["Supabase"].status == "fail"
    out = []
    assert doctor.report(checks, out.append) == 1
    assert not any(TOKEN in line or "sbp_bad" in line for line in out)


def test_doctor_does_not_create_the_database(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("SECWATCH_"):
            monkeypatch.delenv(k)
    s = Settings(host_root=str(tmp_path), db_path=str(tmp_path / "nope" / "secwatch.db"))
    assert doctor.check_storage(s).status == "warn"
    assert not (tmp_path / "nope").exists()
