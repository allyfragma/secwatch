"""Settings from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _list(name: str, default: str) -> list[str]:
    return [p.strip() for p in _env(name, default).split(",") if p.strip()]


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _bool(name: str, default: bool = False) -> bool:
    return _env(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    host_root: str = field(default_factory=lambda: _env("SECWATCH_HOST_ROOT", "/host"))
    db_path: str = field(default_factory=lambda: _env("SECWATCH_DB", "/data/secwatch.db"))
    auth_logs: list = field(default_factory=list)
    nginx_logs: list = field(default_factory=list)
    fail2ban_logs: list = field(default_factory=list)
    caddy_logs: list = field(default_factory=list)
    # Timezone of the server's syslog/fail2ban timestamps that carry no offset.
    syslog_tz: str = field(default_factory=lambda: _env("SECWATCH_SYSLOG_TZ", "UTC"))
    # Timezone in which the dashboard counts "a day".
    timezone: str = field(default_factory=lambda: _env("SECWATCH_TIMEZONE", "UTC"))
    geoip_country_db: str = field(default_factory=lambda: _env("SECWATCH_GEOIP_COUNTRY_DB", "/data/GeoLite2-Country.mmdb"))
    geoip_asn_db: str = field(default_factory=lambda: _env("SECWATCH_GEOIP_ASN_DB", "/data/GeoLite2-ASN.mmdb"))
    # Download and refresh the free DB-IP Lite databases into the data directory.
    geoip_auto_update: bool = field(default_factory=lambda: _bool("SECWATCH_GEOIP_AUTO_UPDATE", True))
    # Your own IPs/networks: "ip-or-cidr label; ..." (and/or an allowlist file, see allowlist.py).
    allowlist: str = field(default_factory=lambda: _env("SECWATCH_ALLOWLIST"))
    allowlist_file: str = field(default_factory=lambda: _env("SECWATCH_ALLOWLIST_FILE"))
    # System log for rare/notable events; new event types are learned for this many days first.
    syslog_logs: list = field(default_factory=list)
    rare_learning_days: int = field(default_factory=lambda: _int("SECWATCH_RARE_LEARNING_DAYS", 3))
    poll_seconds: int = field(default_factory=lambda: _int("SECWATCH_POLL_SECONDS", 30))
    web_host: str = field(default_factory=lambda: _env("SECWATCH_WEB_HOST", "0.0.0.0"))
    web_port: int = field(default_factory=lambda: _int("SECWATCH_WEB_PORT", 8088))
    web_user: str = field(default_factory=lambda: _env("SECWATCH_WEB_USER", "admin"))
    web_password: str = field(default_factory=lambda: _env("SECWATCH_WEB_PASSWORD"))
    allow_no_auth: bool = field(default_factory=lambda: _bool("SECWATCH_ALLOW_NO_AUTH"))
    telegram_token: str = field(default_factory=lambda: _env("SECWATCH_TELEGRAM_TOKEN"))
    telegram_chat_id: str = field(default_factory=lambda: _env("SECWATCH_TELEGRAM_CHAT_ID"))
    digest_hour: int = field(default_factory=lambda: _int("SECWATCH_DIGEST_HOUR", 9))
    spike_threshold: int = field(default_factory=lambda: _int("SECWATCH_SPIKE_THRESHOLD", 60))
    # Optional HTTP receiver of alerts and summaries (your own app).
    erp_ingest_url: str = field(default_factory=lambda: _env("SECWATCH_ERP_INGEST_URL"))
    erp_ingest_key: str = field(default_factory=lambda: _env("SECWATCH_ERP_INGEST_KEY"))
    erp_summary_minutes: int = field(default_factory=lambda: _int("SECWATCH_ERP_SUMMARY_MINUTES", 5))
    supabase_token: str = field(default_factory=lambda: _env("SECWATCH_SUPABASE_TOKEN"))
    supabase_project_ref: str = field(default_factory=lambda: _env("SECWATCH_SUPABASE_PROJECT_REF"))
    supabase_api: str = field(default_factory=lambda: _env("SECWATCH_SUPABASE_API", "https://api.supabase.com"))
    supabase_poll_minutes: int = field(default_factory=lambda: _int("SECWATCH_SUPABASE_POLL_MINUTES", 15))
    supabase_auth_logs: bool = field(default_factory=lambda: _bool("SECWATCH_SUPABASE_AUTH_LOGS", True))
    # Language of the dashboard, alerts and findings: "en" (default) or "ru".
    lang: str = field(default_factory=lambda: _env("SECWATCH_LANG", "en"))

    def __post_init__(self) -> None:
        root = self.host_root.rstrip("/")
        if not self.auth_logs:
            self.auth_logs = _list("SECWATCH_AUTH_LOGS", f"{root}/var/log/auth.log")
        if not self.nginx_logs:
            self.nginx_logs = _list("SECWATCH_NGINX_LOGS", f"{root}/var/log/nginx/access.log")
        if not self.caddy_logs:
            self.caddy_logs = _list("SECWATCH_CADDY_LOGS", f"{root}/var/log/caddy/access.json")
        if not self.syslog_logs:
            self.syslog_logs = _list("SECWATCH_SYSLOG_LOGS", f"{root}/var/log/syslog")
        if not self.fail2ban_logs:
            self.fail2ban_logs = _list("SECWATCH_FAIL2BAN_LOGS", f"{root}/var/log/fail2ban.log")

    def host_path(self, absolute: str) -> str:
        """Map an absolute path on the monitored host to its mount inside the container."""
        return self.host_root.rstrip("/") + "/" + absolute.lstrip("/")

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)

    @property
    def erp_enabled(self) -> bool:
        return bool(self.erp_ingest_key and self.erp_ingest_url)

    @property
    def supabase_enabled(self) -> bool:
        return bool(self.supabase_token and self.supabase_project_ref)
