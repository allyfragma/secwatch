"""SQLite storage. One short-lived connection per unit of work (WAL mode)."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .models import Event, Finding

SCHEMA = """
create table if not exists events (
  id integer primary key,
  ts text not null,               -- UTC ISO-8601
  source text not null,           -- ssh | nginx | fail2ban | supabase
  kind text not null,
  ip text,
  target text,
  username text,
  status integer,
  conn text,                      -- connection id (sshd pid) to count attempts once
  detail text,
  severity text not null default 'info',
  key text not null unique
);
create index if not exists ix_events_ts on events(ts);
create index if not exists ix_events_ip_ts on events(ip, ts);
create index if not exists ix_events_kind_ts on events(kind, ts);
create table if not exists cursors (path text primary key, inode integer, offset integer, updated text);
create table if not exists traffic (hour text, source text, total integer not null, primary key (hour, source));
create table if not exists findings (
  source text, code text, severity text, title text, detail text, fix text, seen text,
  primary key (source, code, title)
);
create table if not exists known_logins (ip text primary key, first_seen text);
create table if not exists alerts_sent (key text primary key, sent text);
create table if not exists meta (k text primary key, v text);
"""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="seconds")


def init_db(path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with connect(path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def connect(path: str):
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("pragma journal_mode=wal")
    conn.execute("pragma foreign_keys=on")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def event_key(*parts: object) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()


def insert_events(conn: sqlite3.Connection, items: list[tuple[str, Event]]) -> int:
    """Insert (key, event) pairs; duplicates by key are ignored. Returns inserted count."""
    before = conn.total_changes
    conn.executemany(
        "insert or ignore into events (ts, source, kind, ip, target, username, status, conn, detail, severity, key)"
        " values (?,?,?,?,?,?,?,?,?,?,?)",
        [
            (iso(e.ts), e.source, e.kind, e.ip, e.target, e.username, e.status, e.conn, e.detail, e.severity, key)
            for key, e in items
        ],
    )
    return conn.total_changes - before


def add_traffic(conn: sqlite3.Connection, source: str, hours: dict[str, int]) -> None:
    for hour, n in hours.items():
        conn.execute(
            "insert into traffic (hour, source, total) values (?,?,?)"
            " on conflict(hour, source) do update set total = total + excluded.total",
            (hour, source, n),
        )


def replace_findings(conn: sqlite3.Connection, source: str, findings: list[Finding]) -> None:
    conn.execute("delete from findings where source = ?", (source,))
    now = iso(utc_now())
    conn.executemany(
        "insert or replace into findings (source, code, severity, title, detail, fix, seen) values (?,?,?,?,?,?,?)",
        [(source, f.code, f.severity, f.title, f.detail, f.fix, now) for f in findings],
    )


def get_meta(conn: sqlite3.Connection, k: str) -> str | None:
    row = conn.execute("select v from meta where k = ?", (k,)).fetchone()
    return row["v"] if row else None


def set_meta(conn: sqlite3.Connection, k: str, v: str) -> None:
    conn.execute("insert into meta (k, v) values (?,?) on conflict(k) do update set v = excluded.v", (k, v))
