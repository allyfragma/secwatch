"""Alerts: new SSH login IP, sensitive file served, attack spikes, new critical
findings and a daily digest.

Delivery: through the ERP (SECWATCH_ERP_INGEST_KEY — the ERP owns the bot,
the chat and which categories are wanted) and/or directly to a Telegram bot
(SECWATCH_TELEGRAM_TOKEN + CHAT_ID). Every alert carries a category.
"""

from __future__ import annotations

import html
import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import httpx

from . import db
from .config import Settings
from .geo import Geo
from .i18n import t
from .models import ATTACK_KINDS
from .summary import build_summary

log = logging.getLogger("secwatch.alerts")

CATEGORIES = ("new_login", "sensitive_file", "spike", "digest", "findings")


class Telegram:
    """Direct delivery to a bot. Kept for installations without the ERP."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.settings = settings
        self.client = client

    def send(self, text: str, category: str = "digest") -> bool:
        if not self.settings.telegram_enabled:
            return False
        url = f"https://api.telegram.org/bot{self.settings.telegram_token}/sendMessage"
        payload = {"chat_id": self.settings.telegram_chat_id, "text": text, "parse_mode": "HTML",
                   "disable_web_page_preview": True}
        try:
            client = self.client or httpx.Client(timeout=15)
            client.post(url, json=payload).raise_for_status()
            return True
        except httpx.HTTPError as exc:  # never log the URL: it contains the token
            log.warning("telegram send failed: %s", type(exc).__name__)
            return False


class ErpSender:
    """POST to the ERP ingest endpoint on the same host."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.settings = settings
        self.client = client

    def _post(self, body: dict) -> bool:
        if not self.settings.erp_enabled:
            return False
        try:
            client = self.client or httpx.Client(timeout=15)
            r = client.post(self.settings.erp_ingest_url, json=body,
                            headers={"Authorization": f"Bearer {self.settings.erp_ingest_key}"})
            r.raise_for_status()
            return True
        except httpx.HTTPError as exc:
            log.warning("erp ingest failed: %s", type(exc).__name__)
            return False

    def send(self, text: str, category: str = "digest") -> bool:
        return self._post({"type": "alert", "category": category, "text": text})

    def push_summary(self, summary: dict) -> bool:
        return self._post({"type": "summary", "summary": compact_summary(summary)})


class Senders:
    """Fan-out to every configured channel; logs when none is configured."""

    def __init__(self, *senders):
        self.senders = senders

    def send(self, text: str, category: str = "digest") -> bool:
        delivered = [s.send(text, category) for s in self.senders]
        if not any(delivered):
            log.info("alert not delivered (no channel or channel refused) [%s]: %s",
                     category, text.replace("\n", " | ")[:300])
        return any(delivered)


def default_sender(settings: Settings) -> Senders:
    return Senders(ErpSender(settings), Telegram(settings))


def compact_summary(s: dict) -> dict:
    return {
        "day": s["day"],
        "risk_score": s["risk"]["score"],
        "risk_level": s["risk"]["level"],
        "attacks": s["attacks"],
        "ssh_attack_conns": s["ssh_attack_conns"],
        "attacker_ips": s["attacker_ips"],
        "bans": s["bans"],
        "web_attacks": s["web_attacks"],
        "ssh_logins": len(s["ssh_logins"]),
        "top_recommendations": [{"severity": r["severity"], "title": r["title"][:240]}
                                for r in s["recommendations"][:5]],
        "hours": s["hours"],
    }


def _once(conn, key: str) -> bool:
    """True if this alert key was not sent before (and marks it sent)."""
    cur = conn.execute("insert or ignore into alerts_sent (key, sent) values (?, ?)", (key, db.iso(db.utc_now())))
    return cur.rowcount == 1


def check_alerts(settings: Settings, sender, geo: Geo, now: datetime | None = None) -> list[str]:
    now = now or db.utc_now()
    tz = ZoneInfo(settings.timezone)
    outgoing: list[tuple[str, str]] = []
    e = html.escape
    with db.connect(settings.db_path) as conn:
        last_id = db.get_meta(conn, "alert_last_id")
        max_id = conn.execute("select coalesce(max(id), 0) from events").fetchone()[0]
        serious = conn.execute("select code, severity, title, detail from findings "
                               "where severity in ('critical', 'high')").fetchall()
        if last_id is None:
            # First run: the backlog becomes the baseline, no alert storm.
            for r in conn.execute("select distinct ip from events where kind = 'ssh_accepted' and ip is not null"):
                conn.execute("insert or ignore into known_logins (ip, first_seen) values (?, ?)",
                             (r["ip"], db.iso(now)))
            for f in serious:
                _once(conn, f"finding:{f['code']}")
            db.set_meta(conn, "alert_last_id", str(max_id))
            return []
        for ev in conn.execute("select * from events where id > ? order by id", (int(last_id),)).fetchall():
            if ev["kind"] == "ssh_accepted":
                fresh = conn.execute("insert or ignore into known_logins (ip, first_seen) values (?, ?)",
                                     (ev["ip"], ev["ts"])).rowcount == 1
                if fresh:
                    g = geo.lookup(ev["ip"])
                    outgoing.append(("new_login", t(
                        "alert.new_login", user=e(ev["username"] or "?"), ip=e(ev["ip"]), country=e(g["country"]),
                        asn=e(g["asn"]), detail=e(ev["detail"] or ""))))
            elif ev["kind"] == "web_sensitive_served" and _once(conn, f"sensitive:{ev['id']}"):
                outgoing.append(("sensitive_file", t(
                    "alert.sensitive_file", target=e(ev["target"] or ""), status=ev["status"], ip=e(ev["ip"] or ""))))
        window = db.iso(now - timedelta(minutes=10))
        kinds = "(" + ",".join(f"'{k}'" for k in ATTACK_KINDS) + ")"
        for r in conn.execute(f"select ip, count(*) n from events where ts >= ? and kind in {kinds} and ip is not null "
                              f"group by ip having n >= ?", (window, settings.spike_threshold)):
            if _once(conn, f"spike:{r['ip']}:{now.astimezone(tz).date()}"):
                g = geo.lookup(r["ip"])
                outgoing.append(("spike", t("alert.spike", count=r["n"], ip=e(r["ip"]), country=e(g["country"]),
                                            asn=e(g["asn"]))))
        for f in serious:
            if _once(conn, f"finding:{f['code']}"):
                outgoing.append(("findings", t("alert.finding", severity=e(f["severity"]), title=e(f["title"]),
                                               detail=e((f["detail"] or "")[:500]))))
        db.set_meta(conn, "alert_last_id", str(max_id))
        local_now = now.astimezone(tz)
        digest_key = f"digest:{local_now.date()}"
        send_digest = local_now.hour >= settings.digest_hour and _once(conn, digest_key)
    if send_digest:
        outgoing.append(("digest", format_digest(build_summary(settings, local_now.date() - timedelta(days=1), geo))))
    for category, text in outgoing:
        sender.send(text, category)
    return [text for _, text in outgoing]


def format_digest(s: dict) -> str:
    e = html.escape
    lines = [t("digest.title", day=s["day"]),
             t("digest.risk", level=s["risk"]["level_label"], score=s["risk"]["score"]),
             t("digest.attacks", attacks=s["attacks"], ips=s["attacker_ips"]),
             t("digest.ssh", attempts=s["ssh_attack_conns"], bans=s["bans"]),
             t("digest.web", attacks=s["web_attacks"], requests=s["web_requests"])]
    if s["ssh_logins"]:
        lines.append(t("digest.logins", count=len(s["ssh_logins"])))
    if s["top_ips"]:
        top = s["top_ips"][0]
        lines.append(t("digest.top_ip", ip=e(top["ip"]), country=e(top["country"]), count=top["count"]))
    serious = [r for r in s["recommendations"] if r["severity"] in ("critical", "high", "medium")]
    if serious:
        lines.append(f"\n<b>{t('digest.fix_header')}</b>")
        lines += [f"• [{r['severity_label']}] {e(r['title'])}" for r in serious[:5]]
    return "\n".join(lines)
