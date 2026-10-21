"""Rare and notable system events from syslog / auth.log.

Two things:
- **Notable events** are recognised by pattern from the first day: reboots,
  out-of-memory kills, disk errors, failed services, user and group changes.
  They become events (source "system") like the attack events.
- **New event types**: every line is reduced to a template (IPs, numbers, ids,
  MACs and hashes masked) and counted per program. During a learning period
  (SECWATCH_RARE_LEARNING_DAYS, default 3) everything is just learned; after
  that a template never seen before is reported as a new kind of event.

Only masked templates and counts are stored, never raw lines.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from . import db
from .models import Event

PROG_RE = re.compile(r"^(?P<prog>[A-Za-z0-9_.@/-]+?)(?:\[\d+\])?:\s+(?P<msg>.*)$")

# Our own log lines (secwatch, httpx, uvicorn) are not events of the host.
OWN_LOG_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} (?:DEBUG|INFO|WARNING|ERROR|CRITICAL) "
                        r"(?:secwatch|httpx|uvicorn)\b")
# SSH is analysed in detail elsewhere; its brute-force usernames would make endless "new" templates.
SKIP_PROGRAMS = {"sshd", "sshd-session"}
REPEATED_RE =re.compile(r"^message repeated \d+ times: \[\s*(?P<msg>.*?)\s*\]$")
UFW_RE = re.compile(r"^\[UFW (?P<action>[A-Z ]+)\].*?\bPROTO=(?P<proto>\S+)")

_MASKS = [
    (re.compile(r"\b\d{4}-\d\d-\d\d(?:[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)?\b"), "<time>"),
    (re.compile(r"\b\d\d:\d\d:\d\d(?:[.,]\d+)?\b"), "<time>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<email>"),
    (re.compile(r"\b(?:[0-9a-f]{2}:){5,}[0-9a-f]{2}\b", re.I), "<mac>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:?)*", re.I), "<ip>"),
    (re.compile(r"\b(?=[0-9a-f]*\d)[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"(?<![\w<])(?=[\w-]*\d)(?=[\w-]*[A-Za-z])[\w-]{16,}"), "<id>"),  # random tokens
    (re.compile(r"\d+(?:\.\d+)*"), "<n>"),
]
MAX_TEMPLATE = 240


def split_program(rest: str) -> tuple[str, str]:
    m = PROG_RE.match(rest)
    return (m.group("prog"), m.group("msg")) if m else ("?", rest)


def template(msg: str) -> str:
    out = msg.strip()
    m = REPEATED_RE.match(out)
    if m:
        out = m.group("msg")
    m = UFW_RE.match(out)
    if m:  # firewall packet logs: fields vary per packet, the kind of event does not
        return f"[UFW {m.group('action')}] PROTO={m.group('proto')}"
    for rx, token in _MASKS:
        out = rx.sub(token, out)
    out = re.sub(r"<n>(?:[KMGTP]i?B|[KMGTP]|ms|us|µs|s|B|%)(?![\w<])", "<n>", out)  # 4K / 120M / 3.5s / 10%
    out = re.sub(r"(<n>[\s,]*){3,}", "<n…> ", out)  # long number lists collapse
    return re.sub(r"\s+", " ", out)[:MAX_TEMPLATE]


# ------------------------------------------------------------ notable ---

PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "docker", "adm", "lxd", "disk", "shadow"}

NOTABLE = [
    # (kind, severity, program regex or None, message regex)
    ("sys_boot", "low", re.compile(r"^kernel$"), re.compile(r"^Linux version \d")),
    ("sys_oom", "medium", re.compile(r"^kernel$"),
     re.compile(r"Out of memory: Killed process \d+ \((?P<target>[^)]+)\)|oom-kill:.*task=(?P<target2>[^,]+)")),
    ("sys_disk_error", "high", None,
     re.compile(r"I/O error|EXT4-fs error|XFS \(\S+\): .*error|Remounting filesystem read-only|"
                r"blk_update_request: (?:critical medium|I/O) error", re.I)),
    ("sys_service_failed", "medium", re.compile(r"^systemd$"),
     re.compile(r"^(?P<target>[\w@.:-]+\.(?:service|socket|timer|mount)): Failed with result '(?P<detail>[^']+)'")),
    ("sys_user_change", "high", re.compile(r"^(?:useradd|userdel|usermod|groupadd|gpasswd|passwd|chpasswd|adduser)$"),
     re.compile(r"new user: name=(?P<target>[^,]+)|delete user '(?P<target2>[^']+)'|"
                r"add '(?P<target3>[^']+)' to group '(?P<group>[^']+)'|"
                r"password changed for (?P<target4>\S+)|new group: name=(?P<target5>[^,]+)")),
]


def notable_event(ts: datetime, prog: str, msg: str) -> Event | None:
    for kind, severity, prog_rx, msg_rx in NOTABLE:
        if prog_rx and not prog_rx.match(prog):
            continue
        m = msg_rx.search(msg)
        if not m:
            continue
        groups = {k: v for k, v in m.groupdict().items() if v}
        target = next((v for k, v in groups.items() if k.startswith("target")), prog)
        if kind == "sys_user_change" and groups.get("group", "").lower() in PRIVILEGED_GROUPS:
            severity = "critical"
        detail = groups.get("detail") or (f"group={groups['group']}" if "group" in groups else template(msg)[:160])
        return Event(ts=ts, source="system", kind=kind, target=target[:120], detail=detail, severity=severity)
    return None


# -------------------------------------------------------- new templates ---

class TemplateTracker:
    """Accumulates template counts during one collection pass; flush() writes them."""

    def __init__(self) -> None:
        self.seen: dict[str, list] = {}

    def observe(self, ts: datetime, prog: str, msg: str) -> None:
        if OWN_LOG_RE.match(msg) or prog in SKIP_PROGRAMS:
            return
        tpl = template(msg)
        key = hashlib.sha1(f"{prog}\x00{tpl}".encode()).hexdigest()
        iso = db.iso(ts)
        item = self.seen.get(key)
        if item is None:
            self.seen[key] = [prog[:60], tpl, iso, iso, 1]
        else:
            item[2], item[3], item[4] = min(item[2], iso), max(item[3], iso), item[4] + 1

    def flush(self, conn: sqlite3.Connection, learning_days: int, now: datetime | None = None) -> int:
        """Upsert counts; returns how many templates were new after the learning period."""
        if not self.seen:
            return 0
        now = now or datetime.now(timezone.utc)
        until = db.get_meta(conn, "rare_learning_until")
        if until is None:
            until = db.iso(now + timedelta(days=learning_days))
            db.set_meta(conn, "rare_learning_until", until)
        learning = db.iso(now) < until
        new = 0
        for key, (prog, tpl, first, last, n) in self.seen.items():
            cur = conn.execute(
                "insert into log_templates (key, program, template, first_seen, last_seen, count, baseline) "
                "values (?,?,?,?,?,?,?) on conflict(key) do nothing", (key, prog, tpl, first, last, n, int(learning)))
            if cur.rowcount:
                new += 0 if learning else 1
            else:
                conn.execute("update log_templates set count = count + ?, last_seen = max(last_seen, ?) where key = ?",
                             (n, last, key))
        self.seen.clear()
        return new


def new_templates(conn: sqlite3.Connection, start: str, end: str, limit: int = 30) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "select program, template, first_seen, last_seen, count from log_templates "
        "where baseline = 0 and first_seen >= ? and first_seen < ? order by first_seen desc limit ?",
        (start, end, limit))]
