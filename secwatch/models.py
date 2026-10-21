from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .i18n import has, t

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "notice": 0}

# Event kinds that count as hostile activity in the daily totals.
ATTACK_KINDS = (
    "ssh_failed_password",
    "ssh_invalid_user",
    "ssh_preauth_fail",
    "ssh_probe",
    "web_scan",
    "web_exploit",
    "web_scanner",
    "web_probe",
    "supabase_auth_fail",
    "supabase_rate_limit",
)
# System events from syslog/auth.log (not attacks); the urgent ones alert at once.
SYSTEM_KINDS = ("sys_boot", "sys_oom", "sys_disk_error", "sys_service_failed", "sys_user_change")
URGENT_SYSTEM_KINDS = ("sys_user_change", "sys_disk_error")
SSH_FAIL_KINDS = ("ssh_failed_password", "ssh_invalid_user", "ssh_preauth_fail", "ssh_probe")
WEB_ATTACK_KINDS = ("web_scan", "web_exploit", "web_scanner", "web_probe")

def kind_label(kind: str) -> str:
    key = f"kind.{kind}.label"
    return t(key) if has(key) else kind


def kind_explanation(kind: str) -> str:
    key = f"kind.{kind}.explain"
    return t(key) if has(key) else ""


@dataclass
class Event:
    ts: datetime
    source: str
    kind: str
    ip: str | None = None
    target: str | None = None
    username: str | None = None
    status: int | None = None
    conn: str | None = None
    detail: str | None = None
    severity: str = "info"


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""


def catalog_finding(code: str, severity: str, key: str | None = None, **params) -> Finding:
    """A Finding whose texts come from finding.<key>.title/detail/fix in the catalog."""
    key = key or code
    return Finding(code, severity, t(f"finding.{key}.title", **params), t(f"finding.{key}.detail", **params),
                   t(f"finding.{key}.fix", **params))
