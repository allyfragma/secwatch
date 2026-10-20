"""Supabase via the Management API (read-only): security advisors and Auth logs.

Requires a personal access token (sbp_...) and the project ref. The token is
read from the environment only and is never logged.

Auth logs come from the unified ClickHouse `logs` table
(GET /v1/projects/{ref}/analytics/endpoints/logs, source = 'auth_logs';
the old logs.all endpoint was removed by Supabase in September 2026). Only
failed (4xx) requests are fetched; IPs and paths, never emails or tokens.
If the token is rejected or the logs API changes, a finding says so instead
of the monitor going silent.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import httpx

from . import db
from .config import Settings
from .i18n import plural, t
from .models import Event, Finding

log = logging.getLogger("secwatch.supabase")

LEVELS = {"ERROR": "high", "WARN": "medium", "INFO": "low"}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
MAX_LISTED = 15

LOGS_ENDPOINT = "/v1/projects/{ref}/analytics/endpoints/logs"
AUTH_LOG_SQL = (
    "select id, timestamp, "
    "log_attributes['status'] as status, log_attributes['path'] as path, "
    "log_attributes['remote_addr'] as ip, log_attributes['msg'] as msg "
    "from logs where source = 'auth_logs' and log_attributes['status'] like '4%' "
    "order by timestamp desc limit 1000"
)
ISO = "%Y-%m-%dT%H:%M:%SZ"  # the endpoint rejects offsets and fractions


def _client(settings: Settings) -> httpx.Client:
    return httpx.Client(base_url=settings.supabase_api, timeout=30,
                        headers={"Authorization": f"Bearer {settings.supabase_token}"})


def fetch_advisors(settings: Settings, client: httpx.Client | None = None) -> list[Finding]:
    own = client is None
    client = client or _client(settings)
    try:
        r = client.get(f"/v1/projects/{settings.supabase_project_ref}/advisors/security")
        r.raise_for_status()
        lints = r.json().get("lints", [])
    finally:
        if own:
            client.close()
    # One finding per lint type: 90 tables with the same intentional pattern
    # are one cause, not 90 risk points.
    groups: dict[str, dict] = {}
    for lint in lints:
        meta = lint.get("metadata") or {}
        obj = ".".join(str(meta[k]) for k in ("schema", "name") if meta.get(k))
        name = str(lint.get("name") or lint.get("title") or "lint")
        g = groups.setdefault(name, {"lint": lint, "objects": [], "severity": "low"})
        if obj:
            g["objects"].append(obj)
        sev = LEVELS.get(str(lint.get("level", "")).upper(), "low")
        if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(g["severity"]):
            g["severity"] = sev
    findings = []
    for name, g in groups.items():
        lint, objects = g["lint"], sorted(set(g["objects"]))
        title = lint.get("title") or lint.get("name") or "Supabase advisor"
        if len(objects) == 1:
            title += f" — {objects[0]}"
        elif objects:
            title += f" — {len(objects)} {plural(len(objects), 'plural.object')}"
        detail = lint.get("detail") or lint.get("description") or ""
        if len(objects) > 1:
            shown = ", ".join(objects[:MAX_LISTED])
            more = t("supabase.and_more", count=len(objects) - MAX_LISTED) if len(objects) > MAX_LISTED else ""
            detail = (lint.get("description") or detail) + " " + t("supabase.objects_list", objects=shown, more=more)
        findings.append(Finding(
            code=f"supabase:{name}" + (f":{objects[0]}" if len(objects) == 1 else ""),
            severity=g["severity"],
            title=f"Supabase: {title}",
            detail=detail,
            fix=lint.get("remediation") or "",
        ))
    return findings


def classify_auth_log(message: str) -> tuple[str, str | None, str | None] | None:
    """Return (kind, ip, detail) for a GoTrue log message, or None if harmless."""
    try:
        data = json.loads(message)
    except (TypeError, ValueError):
        data = {"msg": message}
    text = " ".join(str(data.get(k, "")) for k in ("msg", "error", "error_code", "component")).lower()
    status = data.get("status")
    try:
        status = int(status) if status not in (None, "") else None
    except (TypeError, ValueError):
        status = None
    ip = data.get("remote_addr") or data.get("ip")
    if status == 429 or "rate limit" in text or "over_request_rate_limit" in text:
        return "supabase_rate_limit", ip, data.get("path")
    if "invalid login credentials" in text or "invalid_credentials" in text or \
            (status in (400, 401) and "/token" in str(data.get("path", ""))):
        return "supabase_auth_fail", ip, data.get("path")
    return None


def fetch_auth_events(settings: Settings, client: httpx.Client | None = None,
                      now: datetime | None = None) -> list[tuple[str, Event]]:
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(hours=1)
    own = client is None
    client = client or _client(settings)
    try:
        r = client.get(LOGS_ENDPOINT.format(ref=settings.supabase_project_ref), params={
            "sql": AUTH_LOG_SQL,
            "iso_timestamp_start": start.strftime(ISO),
            "iso_timestamp_end": now.strftime(ISO),
        })
        r.raise_for_status()
        body = r.json()
        if body.get("error"):
            raise ValueError(f"logs query rejected: {str(body['error'])[:120]}")
        rows = body.get("result") or []
    finally:
        if own:
            client.close()
    out = []
    for row in rows:
        hit = classify_auth_log(json.dumps({k: row.get(k) for k in ("status", "path", "msg")}
                                           | {"remote_addr": row.get("ip")}))
        if not hit:
            continue
        kind, ip, detail = hit
        raw_ts = row.get("timestamp")
        if isinstance(raw_ts, (int, float)):  # microseconds since epoch
            ts = datetime.fromtimestamp(raw_ts / 1_000_000, timezone.utc)
        else:
            ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        out.append((db.event_key("supabase", raw_ts, row.get("id") or json.dumps(row, sort_keys=True)),
                    Event(ts=ts, source="supabase", kind=kind, ip=ip, target="auth", detail=detail,
                          severity="low")))
    return out


def poll_supabase(settings: Settings) -> None:
    if not settings.supabase_enabled:
        return
    findings: list[Finding] = []
    with _client(settings) as client:
        try:
            findings = fetch_advisors(settings, client)
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("supabase advisors failed: %s", type(exc).__name__)
            findings.append(_access_finding("advisors", exc))
        if settings.supabase_auth_logs:
            try:
                items = fetch_auth_events(settings, client)
                with db.connect(settings.db_path) as conn:
                    db.insert_events(conn, items)
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("supabase auth logs failed: %s", type(exc).__name__)
                findings.append(_access_finding("auth_logs", exc))
    with db.connect(settings.db_path) as conn:
        db.replace_findings(conn, "supabase", findings)


def _access_finding(part: str, exc: Exception) -> Finding:
    status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
    what = t(f"supabase.part.{part}")
    if status in (401, 403):
        return Finding(f"supabase_token:{part}", "medium", t("supabase.token_rejected.title", what=what),
                       t("supabase.token_rejected.detail"), t("supabase.token_rejected.fix"))
    return Finding(f"supabase_unavailable:{part}", "medium", t("supabase.unavailable.title", what=what),
                   t("supabase.unavailable.detail", error=status or type(exc).__name__),
                   t("supabase.unavailable.fix"))
