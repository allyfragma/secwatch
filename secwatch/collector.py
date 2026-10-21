"""Incremental reading of log files (survives restarts and log rotation)."""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo

from . import db
from .config import Settings
from .models import Event
from .parsers import parse_caddy, parse_fail2ban, parse_nginx, parse_ssh, parse_syslog_ts
from .syslograre import TemplateTracker, notable_event, split_program

log = logging.getLogger("secwatch.collector")

CHUNK = 8 * 1024 * 1024


HEAD_BYTES = 128


def _fingerprint(start: bytes) -> str:
    return f"{len(start)}:{hashlib.sha1(start).hexdigest()}"


def _same_start(stored: str | None, start: bytes) -> bool:
    """False if the first bytes changed since the cursor was saved (truncated and rewritten)."""
    if not stored:
        return True  # cursor from before 0.2.2
    length, _, digest = stored.partition(":")
    n = int(length or 0)
    return len(start) >= n and hashlib.sha1(start[:n]).hexdigest() == digest


def _read_chunk(conn: sqlite3.Connection, path: str) -> tuple[list[tuple[int, str]], bool]:
    """Read the next complete lines of `path` after the stored cursor.

    Returns ([(byte_offset, line), ...], more_available). A new inode or a
    file shorter than the cursor means rotation/truncation: start from 0.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return [], False
    row = conn.execute("select inode, offset, head from cursors where path = ?", (path,)).fetchone()
    with open(path, "rb") as fh:
        start = fh.read(HEAD_BYTES)
        offset = 0
        if row and row["inode"] == st.st_ino and st.st_size >= row["offset"] and _same_start(row["head"], start):
            offset = row["offset"]
        if offset >= st.st_size:
            return [], False
        fh.seek(offset)
        data = fh.read(CHUNK)
    end = data.rfind(b"\n")
    if end < 0:
        return [], False
    data = data[: end + 1]
    lines, pos = [], offset
    for raw in data.split(b"\n")[:-1]:
        lines.append((pos, raw.decode("utf-8", "replace").rstrip("\r")))
        pos += len(raw) + 1
    conn.execute(
        "insert into cursors (path, inode, offset, updated, head) values (?,?,?,?,?)"
        " on conflict(path) do update set inode = excluded.inode, offset = excluded.offset,"
        " updated = excluded.updated, head = excluded.head",
        (path, st.st_ino, pos, db.iso(db.utc_now()), _fingerprint(start)),
    )
    return lines, pos < st.st_size


def _collect_file(conn: sqlite3.Connection, path: str, source: str, parse) -> int:
    inserted = 0
    while True:
        lines, more = _read_chunk(conn, path)
        if not lines:
            return inserted
        inode = os.stat(path).st_ino
        events: list[tuple[str, Event]] = []
        hours: Counter = Counter()
        for offset, line in lines:
            ts, event = parse(line)
            if ts is not None and source in ("nginx", "caddy"):
                hours[ts.strftime("%Y-%m-%dT%H")] += 1
            if event is not None:
                # The line is part of the key: after copytruncate the same offsets
                # are reused by new lines, which must not look like repeats.
                events.append((db.event_key(path, inode, offset, line), event))
        inserted += db.insert_events(conn, events)
        if hours:
            db.add_traffic(conn, source, dict(hours))
        conn.commit()
        if not more:
            return inserted


def collect_logs(settings: Settings, now: datetime | None = None) -> dict[str, int]:
    syslog_tz = ZoneInfo(settings.syslog_tz)
    tracker = TemplateTracker()

    def system_line(line: str):
        """Any syslog-format line: learn its template, return a notable event if it is one."""
        parsed = parse_syslog_ts(line, syslog_tz, now)
        if parsed is None:
            return None, None
        ts, rest = parsed
        prog, msg = split_program(rest)
        tracker.observe(ts, prog, msg)
        return ts, notable_event(ts, prog, msg)

    def ssh(line: str):
        e = parse_ssh(line, syslog_tz, now)
        if e is None:  # user/group/password changes also live in auth.log
            return system_line(line)
        return e.ts, e

    def f2b(line: str):
        e = parse_fail2ban(line, syslog_tz)
        return (e.ts if e else None), e

    stats: dict[str, int] = {}
    with db.connect(settings.db_path) as conn:
        for source, paths, parse in (
            ("ssh", settings.auth_logs, ssh),
            ("nginx", settings.nginx_logs, parse_nginx),
            ("caddy", settings.caddy_logs, parse_caddy),
            ("fail2ban", settings.fail2ban_logs, f2b),
            ("syslog", settings.syslog_logs, system_line),
        ):
            for path in paths:
                try:
                    n = _collect_file(conn, path, source, parse)
                except PermissionError:
                    log.warning("no permission to read %s", path)
                    stats[path] = -1
                    continue
                stats[path] = n
                if n:
                    log.info("%s: %d new events from %s", source, n, path)
        new = tracker.flush(conn, settings.rare_learning_days, now)
        if new:
            log.info("system: %d new kinds of log events", new)
    return stats
