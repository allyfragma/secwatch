"""`secwatch setup`: interactive first-run configuration.

Finds the logs and timezone on this host, creates the dashboard password,
connects Telegram by token only (the chat is discovered after /start) and
optionally Supabase, then writes the settings file. Secrets are typed hidden
and never printed back.
"""

from __future__ import annotations

import getpass
import glob
import os
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from .envfile import find_env_file, read_env, update_env

TELEGRAM_API = "https://api.telegram.org"
SUPABASE_API = "https://api.supabase.com"
ROTATED = re.compile(r"-\d{4}-\d{2}-\d{2}")


# ----------------------------------------------------------------- detect ---

def _p(root: str, path: str) -> str:
    return root.rstrip("/") + "/" + path.lstrip("/")


def _first(root: str, candidates: list[str]) -> list[str]:
    return [c for c in candidates if os.path.exists(_p(root, c))][:1]


def detect_logs(root: str = "/") -> dict[str, list[str]]:
    caddy = []
    for pattern in ("/var/log/caddy/*.json", "/var/log/caddy/*.log", "/var/log/caddy/*/*.json", "/var/log/caddy/*/*.log"):
        for path in sorted(glob.glob(_p(root, pattern))):
            if ROTATED.search(os.path.basename(path)):
                continue  # rotated copy such as access-2026-10-20T08-07-28.700.json
            caddy.append("/" + os.path.relpath(path, root).replace(os.sep, "/"))
    return {
        "SECWATCH_AUTH_LOGS": _first(root, ["/var/log/auth.log", "/var/log/secure"]),
        "SECWATCH_NGINX_LOGS": _first(root, ["/var/log/nginx/access.log"]),
        "SECWATCH_CADDY_LOGS": caddy,
        "SECWATCH_FAIL2BAN_LOGS": _first(root, ["/var/log/fail2ban.log"]),
        "SECWATCH_SYSLOG_LOGS": _first(root, ["/var/log/syslog", "/var/log/messages"]),
    }


def detect_timezone(root: str = "/") -> str:
    try:
        with open(_p(root, "/etc/timezone"), encoding="utf-8") as fh:
            value = fh.read().strip()
            if value:
                return value
    except OSError:
        pass
    try:
        target = os.readlink(_p(root, "/etc/localtime"))
        if "zoneinfo/" in target:
            return target.split("zoneinfo/", 1)[1]
    except OSError:
        pass
    return "UTC"


# --------------------------------------------------------------- external ---

class SetupError(Exception):
    pass


def telegram_bot_name(client: httpx.Client, token: str) -> str:
    try:
        r = client.post(f"{TELEGRAM_API}/bot{token}/getMe")
    except httpx.HTTPError:
        raise SetupError("Telegram is not reachable from this server.") from None
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if not data.get("ok"):
        raise SetupError("Telegram rejected the token. Copy it again from @BotFather.")
    return data["result"].get("username") or data["result"].get("first_name") or "bot"


def telegram_wait_for_chat(client: httpx.Client, token: str, timeout: float = 180, poll: float = 3,
                           sleep: Callable[[float], None] = time.sleep) -> tuple[str, str] | None:
    """Return (chat_id, title) of the most recent chat that wrote to the bot."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            r = client.post(f"{TELEGRAM_API}/bot{token}/getUpdates",
                            json={"timeout": 0, "allowed_updates": ["message", "my_chat_member", "channel_post"]})
            data = r.json()
        except (httpx.HTTPError, ValueError):
            data = {}
        if data.get("error_code") == 409:
            raise SetupError("This bot has a webhook, so it is already used by an app. Create a separate bot for alerts.")
        for update in reversed(data.get("result") or []):
            item = update.get("message") or update.get("channel_post") or update.get("my_chat_member") or {}
            chat = item.get("chat") or {}
            if "id" in chat:
                title = chat.get("title") or " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")]))
                return str(chat["id"]), title or str(chat["id"])
        if time.monotonic() >= deadline:
            return None
        sleep(poll)


def telegram_send(client: httpx.Client, token: str, chat_id: str, text: str) -> bool:
    try:
        r = client.post(f"{TELEGRAM_API}/bot{token}/sendMessage", json={"chat_id": chat_id, "text": text})
        return bool(r.json().get("ok"))
    except (httpx.HTTPError, ValueError):
        return False


def supabase_check(client: httpx.Client, token: str, ref: str) -> None:
    try:
        r = client.get(f"{SUPABASE_API}/v1/projects/{ref}/advisors/security",
                       headers={"Authorization": f"Bearer {token}"})
    except httpx.HTTPError:
        raise SetupError("Supabase API is not reachable from this server.") from None
    if r.status_code in (401, 403):
        raise SetupError("Supabase rejected the token (or it has no access to this project).")
    if r.status_code == 404:
        raise SetupError("Project not found: check the project ref (the part before .supabase.co).")
    if r.status_code >= 400:
        raise SetupError(f"Supabase answered {r.status_code}.")


# ----------------------------------------------------------------- wizard ---

@dataclass
class Io:
    ask: Callable[[str], str] = input
    ask_secret: Callable[[str], str] = getpass.getpass
    say: Callable[[str], None] = print

    def question(self, prompt: str, default: str = "") -> str:
        value = self.ask(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
        return value or default

    def yes(self, prompt: str, default: bool = True) -> bool:
        value = self.question(f"{prompt} (y/n)", "y" if default else "n").lower()
        return value.startswith(("y", "д"))


def run_setup(env_path: str | None = None, root: str = "/", io: Io | None = None,
              client: httpx.Client | None = None) -> str:
    io = io or Io()
    path = find_env_file(env_path)
    current = read_env(path)
    own = client is None
    client = client or httpx.Client(timeout=20)
    updates: dict[str, str | None] = {}
    try:
        io.say(f"secwatch setup — settings file: {path}\n")

        lang = io.question("Language of the dashboard and alerts: en / ru", current.get("SECWATCH_LANG", "en"))
        updates["SECWATCH_LANG"] = "ru" if lang.lower().startswith("r") else "en"

        found = detect_logs(root)
        io.say("Logs found on this server:")
        for key, paths in found.items():
            label = key.removeprefix("SECWATCH_").removesuffix("_LOGS").lower()
            io.say(f"  {label:9} {', '.join(paths) if paths else '— not found'}")
            if paths:
                # Paths as the monitor sees them (under /host in Docker).
                updates[key] = ",".join(_p(root, path) if root != "/" else path for path in paths)
        if not found["SECWATCH_AUTH_LOGS"]:
            io.say("  ! No SSH log file. On systems without rsyslog (e.g. Debian 12) install it: apt install rsyslog")

        tz = detect_timezone(root)
        updates["SECWATCH_SYSLOG_TZ"] = tz
        updates["SECWATCH_TIMEZONE"] = io.question("Timezone for daily totals", current.get("SECWATCH_TIMEZONE", tz))

        _offer_own_ip(io, path)

        if not current.get("SECWATCH_WEB_PASSWORD"):
            updates["SECWATCH_WEB_USER"] = current.get("SECWATCH_WEB_USER", "admin")
            updates["SECWATCH_WEB_PASSWORD"] = secrets.token_urlsafe(24)
            io.say("\nDashboard password created (stored in the settings file).")

        io.say("")
        if io.yes("Send alerts to Telegram?", default=not current.get("SECWATCH_TELEGRAM_TOKEN")):
            _setup_telegram(io, client, updates, updates["SECWATCH_LANG"])

        io.say("")
        if io.yes("Check Supabase (security advisors and failed logins)?", default=False):
            _setup_supabase(io, client, updates)

        # The systemd service reads the file via group secwatch; elsewhere keep it owner-only.
        update_env(path, updates, mode=0o640 if path.startswith("/etc/secwatch/") else 0o600,
                   group="secwatch" if path.startswith("/etc/secwatch/") else None)
        io.say(f"\nSaved {path}.")
        if path.startswith("/etc/secwatch/"):
            io.say("Next: sudo systemctl restart secwatch && sudo secwatch doctor")
        else:
            io.say("Next: sudo docker compose up -d && sudo docker compose exec secwatch python -m secwatch doctor")
        io.say("Dashboard (only via SSH tunnel): ssh -L 8088:127.0.0.1:8088 root@<server>  →  http://localhost:8088")
        return path
    finally:
        if own:
            client.close()


def _offer_own_ip(io: Io, env_path: str) -> None:
    """Over SSH, offer to put the admin's current IP on the allowlist (it then never counts as an attacker)."""
    client = os.environ.get("SSH_CLIENT", "").split()
    if not client:
        return
    ip = client[0]
    allow_path = os.path.join(os.path.dirname(os.path.abspath(env_path)), "allowlist.txt")
    try:
        with open(allow_path, encoding="utf-8") as fh:
            if any(line.split("#")[0].split()[:1] == [ip] for line in fh):
                return
    except OSError:
        pass
    io.say("")
    if not io.yes(f"You are connected from {ip}. Add it to the allowlist (your own IP, not an attacker)?"):
        return
    label = io.question("Label for it", "admin")
    new = not os.path.exists(allow_path)
    with open(allow_path, "a", encoding="utf-8") as fh:
        if new:
            fh.write("# Own IPs and networks: one per line, optional label. See README.\n")
        fh.write(f"{ip} {label}\n")
    if new and allow_path.startswith("/etc/secwatch/") and hasattr(os, "geteuid") and os.geteuid() == 0:
        import grp
        try:
            os.chown(allow_path, 0, grp.getgrnam("secwatch").gr_gid)
            os.chmod(allow_path, 0o640)
        except KeyError:
            pass
    io.say(f"  ✓ {ip} added to {allow_path}")


def _setup_telegram(io: Io, client: httpx.Client, updates: dict, lang: str) -> None:
    io.say("Create a NEW bot in @BotFather (/newbot) — do not reuse a bot that an app already uses.")
    for _ in range(3):
        token = io.ask_secret("Bot token (hidden): ").strip()
        try:
            name = telegram_bot_name(client, token)
            break
        except SetupError as exc:
            io.say(f"  ✗ {exc}")
    else:
        io.say("  Telegram skipped.")
        return
    io.say(f"  ✓ @{name}. Now open Telegram and send /start to @{name} (or add it to a group). Waiting up to 3 minutes…")
    try:
        found = telegram_wait_for_chat(client, token)
    except SetupError as exc:
        io.say(f"  ✗ {exc}")
        return
    if not found:
        io.say("  ✗ No message reached the bot. Run `secwatch setup` again when ready.")
        return
    chat_id, title = found
    text = "✅ secwatch: alerts will arrive in this chat." if lang == "en" else "✅ secwatch: оповещения будут приходить в этот чат."
    sent = telegram_send(client, token, chat_id, text)
    io.say(f"  ✓ Chat: {title}" + (" — test message sent." if sent else " — but the test message failed."))
    updates["SECWATCH_TELEGRAM_TOKEN"] = token
    updates["SECWATCH_TELEGRAM_CHAT_ID"] = chat_id


def _setup_supabase(io: Io, client: httpx.Client, updates: dict) -> None:
    io.say("Personal access token: supabase.com/dashboard/account/tokens (a read-only member's token is enough;")
    io.say("set an expiry). Project ref: the part before .supabase.co in your project URL.")
    ref = io.question("Project ref").strip()
    token = io.ask_secret("Access token sbp_… (hidden): ").strip()
    try:
        supabase_check(client, token, ref)
    except SetupError as exc:
        io.say(f"  ✗ {exc} Supabase skipped.")
        return
    io.say("  ✓ Supabase connected.")
    updates["SECWATCH_SUPABASE_TOKEN"] = token
    updates["SECWATCH_SUPABASE_PROJECT_REF"] = ref
