"""Allowlist: your own IPs and networks (office, VPN, CI, monitoring).

Their events are kept, but they are not counted as attacks, do not raise spikes
or "login from a new IP" alerts, and are shown as known in the logins table.

Sources (merged): SECWATCH_ALLOWLIST (entries separated by ';' or new lines)
and the allowlist file (SECWATCH_ALLOWLIST_FILE, default allowlist.txt next to
the settings file or in the data directory). One entry per line:

    203.0.113.5          office
    198.51.100.0/24      VPN    # comments are fine too
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import sqlite3
from dataclasses import dataclass, field

from . import db

DEFAULT_FILES = ("/etc/secwatch/allowlist.txt",)


@dataclass
class Allowlist:
    entries: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_text: str = ""

    def match(self, ip: str | None) -> str | None:
        """The label of the entry that covers `ip` ('' if unlabeled), or None."""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, label in self.entries:
            if addr.version == net.version and addr in net:
                return label
        return None

    @property
    def signature(self) -> str:
        return hashlib.sha1(self.source_text.encode()).hexdigest()

    def __len__(self) -> int:
        return len(self.entries)


def parse(text: str) -> Allowlist:
    al = Allowlist(source_text=text)
    for raw in text.replace(";", "\n").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        value, *rest = line.split(None, 1)
        try:
            al.entries.append((ipaddress.ip_network(value, strict=False), rest[0].strip() if rest else ""))
        except ValueError:
            al.errors.append(value)
    return al


def allowlist_paths(settings) -> list[str]:
    if settings.allowlist_file:
        return [settings.allowlist_file]
    data_dir = os.path.dirname(settings.db_path) or "."
    return [*DEFAULT_FILES, os.path.join(data_dir, "allowlist.txt")]


def load(settings) -> Allowlist:
    parts = [settings.allowlist or ""]
    for path in allowlist_paths(settings):
        try:
            with open(path, encoding="utf-8") as fh:
                parts.append(fh.read())
        except OSError:
            continue
    return parse("\n".join(parts))


def mark_events(conn: sqlite3.Connection, al: Allowlist) -> int:
    """Set events.allowed for rows not marked yet; everything again when the list changed."""
    if db.get_meta(conn, "allowlist_signature") != al.signature:
        conn.execute("update events set allowed = 0 where allowed = 1")
        db.set_meta(conn, "allowlist_marked_id", "0")
        db.set_meta(conn, "allowlist_signature", al.signature)
    last = int(db.get_meta(conn, "allowlist_marked_id") or 0)
    max_id = conn.execute("select coalesce(max(id), 0) from events").fetchone()[0]
    marked = 0
    if len(al) and max_id > last:
        ips = [r[0] for r in conn.execute(
            "select distinct ip from events where id > ? and id <= ? and ip is not null", (last, max_id))]
        for ip in ips:
            if al.match(ip) is not None:
                marked += conn.execute("update events set allowed = 1 where ip = ? and id > ? and id <= ?",
                                       (ip, last, max_id)).rowcount
    db.set_meta(conn, "allowlist_marked_id", str(max_id))
    return marked
