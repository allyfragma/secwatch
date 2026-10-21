"""Background loop: collect logs, audit host, poll Supabase, send alerts, push summary to the ERP."""

from __future__ import annotations

import logging
import os
import threading
import time

from . import allowlist, db
from .alerts import ErpSender, check_alerts, default_sender
from .audit import audit_host
from .collector import collect_logs
from .config import Settings
from .geo import Geo
from .geoupdate import update_dbip
from .models import catalog_finding
from .summary import build_summary
from .supabase import poll_supabase

log = logging.getLogger("secwatch.worker")

GEO_CHECK_SECONDS = 24 * 3600


def run_once(settings: Settings, sender, geo: Geo, poll_supabase_now: bool) -> None:
    stats = collect_logs(settings)
    unreadable = [catalog_finding(f"unreadable:{path}", "medium", "unreadable", path=path)
                  for path, n in stats.items() if n < 0]
    with db.connect(settings.db_path) as conn:
        db.replace_findings(conn, "host", audit_host(settings) + unreadable)
        db.set_meta(conn, "last_collect", db.iso(db.utc_now()))
    if poll_supabase_now:
        poll_supabase(settings)
    al = allowlist.load(settings)
    with db.connect(settings.db_path) as conn:
        allowlist.mark_events(conn, al)  # before alerts: own IPs must not alert
        if al.errors:
            db.replace_findings(conn, "allowlist", [catalog_finding(
                "allowlist_invalid", "low", "allowlist_invalid", entries=", ".join(al.errors[:5]))])
        else:
            db.replace_findings(conn, "allowlist", [])
    check_alerts(settings, sender, geo)


def loop(settings: Settings, stop: threading.Event) -> None:
    sender = default_sender(settings)
    erp = ErpSender(settings)
    geo = Geo.for_settings(settings)
    last_supabase = 0.0
    last_summary = 0.0
    last_geo = None
    while not stop.is_set():
        started = time.monotonic()
        if settings.geoip_auto_update and (last_geo is None or started - last_geo >= GEO_CHECK_SECONDS):
            # Daily check; a download happens only when a file is missing or a month old.
            try:
                update_dbip(os.path.dirname(settings.db_path) or ".")
            except Exception:  # enrichment is optional; never stop collection for it
                log.exception("geoip update failed")
            last_geo = started
        due = settings.supabase_enabled and started - last_supabase >= settings.supabase_poll_minutes * 60
        try:
            run_once(settings, sender, geo, due)
            if due:
                last_supabase = started
            if settings.erp_enabled and started - last_summary >= settings.erp_summary_minutes * 60:
                if erp.push_summary(build_summary(settings, geo=geo)):
                    last_summary = started
        except Exception:  # keep the monitor alive; the traceback goes to the service log
            log.exception("collection cycle failed")
        stop.wait(max(1.0, settings.poll_seconds - (time.monotonic() - started)))


def start(settings: Settings) -> threading.Event:
    stop = threading.Event()
    threading.Thread(target=loop, args=(settings, stop), name="secwatch-worker", daemon=True).start()
    return stop
