"""DB-IP download/refresh and live reload, with a fake .mmdb reader (JSON files)."""

import gzip
import json
import os
import time
from datetime import date

import httpx
import pytest

from secwatch import geo as geo_mod
from secwatch import geoupdate
from secwatch.geo import DBIP_ASN, DBIP_COUNTRY, Geo


class FakeReader:
    def __init__(self, path):
        with open(path, encoding="utf-8") as fh:
            self.data = json.load(fh)  # invalid content raises, like a broken .mmdb

    def get(self, ip):
        return self.data.get(ip)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeMaxmind:
    open_database = FakeReader


@pytest.fixture(autouse=True)
def fake_maxmind(monkeypatch):
    monkeypatch.setattr(geo_mod, "maxminddb", FakeMaxmind)
    monkeypatch.setattr(geoupdate, "maxminddb", FakeMaxmind)


COUNTRY = {"1.1.1.1": {"country": {"iso_code": "AU", "names": {"en": "Australia"}}},
           "198.51.100.7": {"country": {"iso_code": "DE", "names": {"en": "Germany", "ru": "Германия"}}}}
ASN = {"1.1.1.1": {"autonomous_system_number": 13335, "autonomous_system_organization": "Cloudflare"},
       "198.51.100.7": {"autonomous_system_number": 24940, "autonomous_system_organization": "Hetzner"}}


def server(published: dict[str, bytes], seen: list[str]):
    def handler(request: httpx.Request):
        seen.append(str(request.url))
        body = published.get(str(request.url).rsplit("/", 1)[1])
        return httpx.Response(200, content=body) if body is not None else httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def gz(obj) -> bytes:
    return gzip.compress(json.dumps(obj).encode())


def test_downloads_current_month_or_falls_back_to_previous(tmp_path):
    seen = []
    client = server({"dbip-country-lite-2026-10.mmdb.gz": gz(COUNTRY),
                     "dbip-asn-lite-2026-09.mmdb.gz": gz(ASN)}, seen)
    result = geoupdate.update_dbip(str(tmp_path), client, today=date(2026, 10, 20))
    assert result == {"country": "updated 2026-10", "asn": "updated 2026-09"}
    assert (tmp_path / DBIP_COUNTRY).exists() and (tmp_path / DBIP_ASN).exists()
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".geo-")]  # temp dirs cleaned

    # Fresh files are not downloaded again.
    seen.clear()
    assert geoupdate.update_dbip(str(tmp_path), client, today=date(2026, 10, 21)) == {"country": "fresh", "asn": "fresh"}
    assert seen == []


def test_january_falls_back_to_december():
    assert geoupdate._months(date(2027, 1, 3)) == ["2027-01", "2026-12"]


def test_broken_download_keeps_the_old_database(tmp_path):
    old = tmp_path / DBIP_COUNTRY
    old.write_text(json.dumps(COUNTRY))
    os.utime(old, (time.time() - 40 * 86400,) * 2)  # stale, so an update is attempted
    client = server({"dbip-country-lite-2026-10.mmdb.gz": gzip.compress(b"not a database"),
                     "dbip-asn-lite-2026-10.mmdb.gz": gz({"1.1.1.1": {"wrong": 1}})}, [])
    result = geoupdate.update_dbip(str(tmp_path), client, today=date(2026, 10, 20))
    assert result["country"].startswith("failed") and result["asn"].startswith("failed")
    assert json.loads(old.read_text()) == COUNTRY
    assert not (tmp_path / DBIP_ASN).exists()


def test_geo_prefers_configured_files_and_reloads_new_downloads(tmp_path, monkeypatch):
    monkeypatch.setattr(geo_mod, "RECHECK_SECONDS", 0)
    geo = Geo([str(tmp_path / "GeoLite2-Country.mmdb"), str(tmp_path / DBIP_COUNTRY)],
              [str(tmp_path / "GeoLite2-ASN.mmdb"), str(tmp_path / DBIP_ASN)])
    assert not geo.available and geo.lookup("198.51.100.7")["country"] == "—"

    (tmp_path / DBIP_COUNTRY).write_text(json.dumps(COUNTRY))
    (tmp_path / DBIP_ASN).write_text(json.dumps(ASN))
    assert geo.lookup("198.51.100.7") == {"country": "DE Германия", "asn": "AS24940 Hetzner"}
    assert geo.attribution_dbip

    (tmp_path / "GeoLite2-Country.mmdb").write_text(json.dumps({"198.51.100.7": {"country": {"iso_code": "NL"}}}))
    assert geo.lookup("198.51.100.7")["country"] == "NL"  # GeoLite2 wins when present
    assert geo.sources == ["GeoLite2-Country.mmdb", DBIP_ASN]


def test_broken_file_does_not_crash_lookup(tmp_path):
    (tmp_path / DBIP_COUNTRY).write_text("garbage")
    geo = Geo([str(tmp_path / DBIP_COUNTRY)], [])
    assert not geo.available
    assert geo.lookup("198.51.100.7") == {"country": "—", "asn": "—"}
