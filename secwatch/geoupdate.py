"""Download and refresh the free DB-IP Lite databases (country + ASN).

DB-IP publishes them monthly at a fixed URL, no account or key needed, under
CC BY 4.0 (the dashboard shows the required attribution). A file is replaced
only after the new one opens and answers a test lookup, so a failed or partial
download never breaks enrichment.
"""

from __future__ import annotations

import gzip
import logging
import os
import shutil
import tempfile
import time
from datetime import date

import httpx

from .geo import DBIP_ASN, DBIP_COUNTRY

try:
    import maxminddb
except ImportError:  # pragma: no cover
    maxminddb = None

log = logging.getLogger("secwatch.geoupdate")

URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
FILES = {"country": DBIP_COUNTRY, "asn": DBIP_ASN}
EXPECTED_KEY = {"country": "country", "asn": "autonomous_system_number"}
MAX_DOWNLOAD = 100 * 1024 * 1024
MAX_AGE_DAYS = 32


def _months(today: date) -> list[str]:
    prev = date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1)
    return [today.strftime("%Y-%m"), prev.strftime("%Y-%m")]


def _fresh(path: str, max_age_days: int) -> bool:
    try:
        return time.time() - os.stat(path).st_mtime < max_age_days * 86400
    except OSError:
        return False


def _validate(path: str, kind: str) -> None:
    if not maxminddb:
        raise RuntimeError("maxminddb is not installed")
    with maxminddb.open_database(path) as reader:
        record = reader.get("1.1.1.1") or reader.get("8.8.8.8") or {}
        if EXPECTED_KEY[kind] not in record:
            raise ValueError(f"{kind}: test lookup has no '{EXPECTED_KEY[kind]}'")


def _download(client: httpx.Client, url: str, dest_gz: str) -> bool:
    with client.stream("GET", url) as response:
        if response.status_code == 404:
            return False
        response.raise_for_status()
        size = 0
        with open(dest_gz, "wb") as fh:
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise ValueError("download is larger than expected")
                fh.write(chunk)
    return True


def update_dbip(data_dir: str, client: httpx.Client | None = None, today: date | None = None,
                max_age_days: int = MAX_AGE_DAYS) -> dict[str, str]:
    """Return {kind: 'fresh' | 'updated <month>' | 'failed: …'}; never raises."""
    own = client is None
    client = client or httpx.Client(timeout=60, follow_redirects=True,
                                    headers={"User-Agent": "secwatch (+https://github.com/allyfragma/secwatch)"})
    results: dict[str, str] = {}
    try:
        os.makedirs(data_dir, exist_ok=True)
        for kind, name in FILES.items():
            target = os.path.join(data_dir, name)
            if _fresh(target, max_age_days):
                results[kind] = "fresh"
                continue
            results[kind] = "failed: not published"
            for month in _months(today or date.today()):
                tmp_dir = tempfile.mkdtemp(prefix=".geo-", dir=data_dir)
                try:
                    gz_path = os.path.join(tmp_dir, "db.mmdb.gz")
                    mmdb_path = os.path.join(tmp_dir, "db.mmdb")
                    if not _download(client, URL.format(kind=kind, month=month), gz_path):
                        continue
                    with gzip.open(gz_path, "rb") as src, open(mmdb_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    _validate(mmdb_path, kind)
                    os.replace(mmdb_path, target)
                    results[kind] = f"updated {month}"
                    break
                except Exception as exc:  # keep the old file, report and move on
                    results[kind] = f"failed: {type(exc).__name__}: {exc}"[:200]
                    break
                finally:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
    finally:
        if own:
            client.close()
    for kind, status in results.items():
        (log.warning if status.startswith("failed") else log.info)("geoip %s: %s", kind, status)
    return results
