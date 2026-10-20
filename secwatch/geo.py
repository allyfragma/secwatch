"""Offline IP enrichment: country and network (ASN) for attacker IPs.

Works with any MaxMind-format (.mmdb) database. By default the monitor
downloads the free DB-IP Lite databases itself (CC BY 4.0, no account, see
geoupdate.py). If GeoLite2-Country.mmdb / GeoLite2-ASN.mmdb are present at the
configured paths, they are preferred. Without any database the dashboard
simply shows "—".
"""

from __future__ import annotations

import ipaddress
import os
import time

from .i18n import get_language, t

try:
    import maxminddb
except ImportError:  # pragma: no cover
    maxminddb = None

DBIP_COUNTRY = "dbip-country-lite.mmdb"
DBIP_ASN = "dbip-asn-lite.mmdb"

# Real private ranges only (ipaddress.is_private also flags documentation and other special ranges).
LOCAL_NETS = [ipaddress.ip_network(n) for n in
              ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]

RECHECK_SECONDS = 60
CACHE_LIMIT = 20000


def _paths(value) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    return [p for p in value if p]


class _Db:
    """First existing file of a candidate list, reopened when it changes on disk."""

    def __init__(self, candidates):
        self.candidates = _paths(candidates)
        self.reader = None
        self.signature = None

    def current_signature(self):
        for path in self.candidates:
            try:
                st = os.stat(path)
            except OSError:
                continue
            return (path, st.st_mtime_ns, st.st_size)
        return None

    def refresh(self) -> bool:
        signature = self.current_signature()
        if signature == self.signature:
            return False
        old, self.reader, self.signature = self.reader, None, signature
        if old is not None:
            old.close()
        if signature and maxminddb:
            try:
                self.reader = maxminddb.open_database(signature[0])
            except Exception:  # a broken file must not stop the monitor
                self.reader = None
        return True

    @property
    def source(self) -> str | None:
        return os.path.basename(self.signature[0]) if self.reader and self.signature else None


class Geo:
    def __init__(self, country_db, asn_db):
        self._country = _Db(country_db)
        self._asn = _Db(asn_db)
        self._cache: dict[str, dict] = {}
        self._checked = 0.0
        self._refresh(force=True)

    @classmethod
    def for_settings(cls, settings) -> "Geo":
        data_dir = os.path.dirname(settings.db_path) or "."
        return cls([settings.geoip_country_db, os.path.join(data_dir, DBIP_COUNTRY)],
                   [settings.geoip_asn_db, os.path.join(data_dir, DBIP_ASN)])

    def _refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._checked < RECHECK_SECONDS:
            return
        self._checked = now
        if self._country.refresh() | self._asn.refresh():
            self._cache.clear()

    @property
    def available(self) -> bool:
        self._refresh()
        return bool(self._country.reader or self._asn.reader)

    @property
    def sources(self) -> list[str]:
        return [s for s in (self._country.source, self._asn.source) if s]

    @property
    def attribution_dbip(self) -> bool:
        return any(s.startswith("dbip-") for s in self.sources)

    def lookup(self, ip: str | None) -> dict:
        self._refresh()
        if ip in self._cache:
            return self._cache[ip]
        result = self._lookup(ip)
        if len(self._cache) >= CACHE_LIMIT:
            self._cache.clear()
        self._cache[ip] = result
        return result

    def _lookup(self, ip: str | None) -> dict:
        if not ip:
            return {"country": "—", "asn": "—"}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"country": "—", "asn": "—"}
        if addr.is_loopback or addr.is_link_local or any(addr in net for net in LOCAL_NETS if addr.version == net.version):
            return {"country": t("geo.local_network"), "asn": "—"}
        country, asn = "—", "—"
        if self._country.reader:
            rec = self._country.reader.get(ip) or {}
            c = rec.get("country") or rec.get("registered_country") or {}
            names = c.get("names") or {}
            country = f"{c.get('iso_code', '')} {names.get(get_language()) or names.get('en') or ''}".strip() or "—"
        if self._asn.reader:
            rec = self._asn.reader.get(ip) or {}
            if rec:
                asn = f"AS{rec.get('autonomous_system_number', '?')} {rec.get('autonomous_system_organization', '')}".strip()
        return {"country": country, "asn": asn}
