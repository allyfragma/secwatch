"""`secwatch doctor`: check that the monitor can see and deliver what it should.

Prints one line per check (ok / warn / fail) with a hint, and exits non-zero
if anything fails. Never prints secrets.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from .config import Settings
from .geo import Geo
from .setup_wizard import SetupError, supabase_check, telegram_bot_name


@dataclass
class Check:
    status: str  # ok | warn | fail
    name: str
    detail: str = ""


SERVICE_USER = "secwatch"


def _can_read_as(path: str, user: str) -> bool:
    """Mode-bit check for the service user when doctor runs as root (root can read anything)."""
    import grp
    import pwd
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return os.access(path, os.R_OK)
    gids = {pw.pw_gid} | {g.gr_gid for g in grp.getgrall() if user in g.gr_mem}
    # Every parent directory needs search (x) permission too.
    parts = os.path.abspath(path).split(os.sep)
    for i in range(2, len(parts) + 1):
        current = os.sep.join(parts[:i]) or os.sep
        st = os.stat(current)
        need = 0o4 if i == len(parts) else 0o1
        if st.st_uid == pw.pw_uid:
            ok = st.st_mode & (need << 6)
        elif st.st_gid in gids:
            ok = st.st_mode & (need << 3)
        else:
            ok = st.st_mode & need
        if not ok:
            return False
    return True


def _readable(path: str) -> str | None:
    try:
        exists = os.path.exists(path)
    except OSError:
        exists = False
    if not exists:
        return "not found"
    as_root = hasattr(os, "geteuid") and os.geteuid() == 0
    ok = _can_read_as(path, SERVICE_USER) if as_root else os.access(path, os.R_OK)
    if not ok:
        return "the monitor cannot read it (give its user read access, e.g. via group adm)"
    return None


def check_logs(settings: Settings) -> list[Check]:
    out = []
    groups = {"SSH log": settings.auth_logs, "nginx log": settings.nginx_logs,
              "Caddy log": settings.caddy_logs, "fail2ban log": settings.fail2ban_logs,
              "system log": settings.syslog_logs}
    readable_any = False
    for name, paths in groups.items():
        for path in paths:
            problem = _readable(path)
            if problem is None:
                readable_any = True
                out.append(Check("ok", name, path))
            elif problem == "not found":
                out.append(Check("warn", name, f"{path}: not found (fine if this service is not used)"))
            else:
                out.append(Check("fail", name, f"{path}: {problem}"))
    if not readable_any:
        out.append(Check("fail", "logs", "no log file is readable: nothing to analyse"))
    return out


def check_storage(settings: Settings) -> Check:
    # Read-only: doctor may run as root and must not create files the service cannot write.
    if not os.path.exists(settings.db_path):
        return Check("warn", "database", f"{settings.db_path}: not created yet (the service creates it on start)")
    try:
        with sqlite3.connect(f"file:{settings.db_path}?mode=ro", uri=True) as conn:
            events = conn.execute("select count(*) from events").fetchone()[0]
            last = conn.execute("select v from meta where k = 'last_collect'").fetchone()
        return Check("ok", "database", f"{events} events, last collection {last[0] if last else 'never'}")
    except sqlite3.Error as exc:
        return Check("fail", "database", f"{settings.db_path}: {exc}")


def check_dashboard(settings: Settings) -> Check:
    if settings.web_password:
        exposed = settings.web_host not in ("127.0.0.1", "::1", "localhost")
        return Check("warn" if exposed else "ok", "dashboard",
                     f"{settings.web_host}:{settings.web_port}" +
                     (" — listens beyond localhost; keep it behind a firewall or SSH tunnel" if exposed else ""))
    if settings.allow_no_auth:
        return Check("warn", "dashboard", "no password (SECWATCH_ALLOW_NO_AUTH)")
    return Check("fail", "dashboard", "SECWATCH_WEB_PASSWORD is empty: the dashboard refuses to start")


def check_geo(settings: Settings) -> Check:
    geo = Geo.for_settings(settings)
    if geo.available:
        return Check("ok", "country/ASN", ", ".join(geo.sources))
    hint = "downloaded automatically on start" if settings.geoip_auto_update else "SECWATCH_GEOIP_AUTO_UPDATE=0"
    return Check("warn", "country/ASN", f"no database yet ({hint})")


def check_telegram(settings: Settings, client: httpx.Client) -> Check | None:
    if not settings.telegram_token:
        return None
    if not settings.telegram_chat_id:
        return Check("fail", "Telegram", "token set but no chat: run `secwatch setup`")
    try:
        return Check("ok", "Telegram", "@" + telegram_bot_name(client, settings.telegram_token))
    except SetupError as exc:
        return Check("fail", "Telegram", str(exc))


def check_supabase(settings: Settings, client: httpx.Client) -> Check | None:
    if not (settings.supabase_token or settings.supabase_project_ref):
        return None
    if not settings.supabase_enabled:
        return Check("fail", "Supabase", "both SECWATCH_SUPABASE_TOKEN and SECWATCH_SUPABASE_PROJECT_REF are needed")
    try:
        supabase_check(client, settings.supabase_token, settings.supabase_project_ref)
        return Check("ok", "Supabase", settings.supabase_project_ref)
    except SetupError as exc:
        return Check("fail", "Supabase", str(exc))


def check_erp(settings: Settings) -> Check | None:
    if not settings.erp_ingest_key:
        return None
    if not settings.erp_ingest_url:
        return Check("fail", "ERP delivery", "SECWATCH_ERP_INGEST_KEY is set but SECWATCH_ERP_INGEST_URL is empty")
    return Check("ok", "ERP delivery", settings.erp_ingest_url)


def run_checks(settings: Settings, client: httpx.Client | None = None) -> list[Check]:
    own = client is None
    client = client or httpx.Client(timeout=15)
    try:
        checks = [check_storage(settings), check_dashboard(settings), *check_logs(settings), check_geo(settings)]
        checks += [c for c in (check_telegram(settings, client), check_supabase(settings, client),
                               check_erp(settings)) if c]
        if not any(c.name in ("Telegram", "ERP delivery") for c in checks):
            checks.append(Check("warn", "alerts", "no Telegram or ERP delivery: alerts are only on the dashboard"))
        return checks
    finally:
        if own:
            client.close()


MARK = {"ok": "✓", "warn": "!", "fail": "✗"}


def report(checks: list[Check], say: Callable[[str], None] = print) -> int:
    for c in checks:
        say(f" {MARK[c.status]} {c.name:13} {c.detail}")
    failed = sum(c.status == "fail" for c in checks)
    say("\nAll good." if not failed else f"\n{failed} problem(s) to fix.")
    return 1 if failed else 0
