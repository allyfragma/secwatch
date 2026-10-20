"""Incremental reading of log files (survives restarts and log rotation)."""

from __future__ import annotations

import logging
import os
import sqlite3
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo

from . import db
from .config import Settings
from .models import Event
from .parsers import parse_caddy, parse_fail2ban, parse_nginx, parse_ssh

log = logging.getLogger("secwatch.collector")

CHUNK = 8 * 1024 * 1024


def _read_chunk(conn: sqlite3.Connection, path: str) -> tuple[list[tuple[int, str]], bool]:
    """Read the next complete lines of `path` after the stored cursor.

    Returns ([(byte_offset, line), ...], more_available). A new inode or a
    file shorter than the cursor means rotation/truncation: start from 0.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return [], False
    row = conn.execute("select inode, offset from cursors where path = ?", (path,)).fetchone()
    offset = 0
    if row and row["inode"] == st.st_ino and st.st_size >= row["offset"]:
        offset = row["offset"]
    if offset >= st.st_size:
        return [], False
    with open(path, "rb") as fh:
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
        "insert into cursors (path, inode, offset, updated) values (?,?,?,?)"
        " on conflict(path) do update set inode = excluded.inode, offset = excluded.offset, updated = excluded.updated",
        (path, st.st_ino, pos, db.iso(db.utc_now())),
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
                events.append((db.event_key(path, inode, offset), event))
        inserted += db.insert_events(conn, events)
        if hours:
            db.add_traffic(conn, source, dict(hours))
        conn.commit()
        if not more:
            return inserted


def collect_logs(settings: Settings, now: datetime | None = None) -> dict[str, int]:
    syslog_tz = ZoneInfo(settings.syslog_tz)

    def ssh(line: str):
        e = parse_ssh(line, syslog_tz, now)
        return (e.ts if e else None), e

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
    return stats
