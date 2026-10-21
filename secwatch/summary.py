"""Daily summary, risk score and recommendations."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from . import allowlist, db
from .config import Settings
from .geo import Geo
from .i18n import t, translate
from .models import (ATTACK_KINDS, SEVERITY_ORDER, SSH_FAIL_KINDS, SYSTEM_KINDS, WEB_ATTACK_KINDS, Finding,
                     kind_explanation, kind_label)
from .syslograre import new_templates

SEVERITY_POINTS = {"critical": 50, "high": 25, "medium": 10, "low": 3, "info": 0}
SEVERITIES = ("critical", "high", "medium", "low", "info")


def severity_label(severity: str, lang: str | None = None) -> str:
    """Severity name in the current language (or in `lang`); unknown values are returned as is."""
    if severity not in SEVERITIES:
        return severity
    return translate(lang, f"severity.{severity}") if lang else t(f"severity.{severity}")


def _rec(code: str, severity: str, key: str, **params) -> Finding:
    return Finding(code, severity, t(f"rec.{key}.title", **params), t(f"rec.{key}.detail", **params),
                   t(f"rec.{key}.fix", **params))


def day_bounds(day: date, tz: ZoneInfo) -> tuple[datetime, datetime]:
    start = datetime.combine(day, time.min, tzinfo=tz).astimezone(timezone.utc)
    end = datetime.combine(day + timedelta(days=1), time.min, tzinfo=tz).astimezone(timezone.utc)
    return start, end


def _in(kinds) -> str:
    return "(" + ",".join("'" + k + "'" for k in kinds) + ")"


def _rows(conn, sql, *args):
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def activity_recommendations(s: dict, settings: Settings) -> list[Finding]:
    recs: list[Finding] = []
    for login in s["ssh_logins"]:
        if login["known"] is not None:
            continue  # own IP from the allowlist
        method = login["method"] or "?"
        if login["had_failures"] and method in ("password", "keyboard-interactive/pam"):
            recs.append(_rec(f"ssh_bruteforce_success:{login['ip']}", "critical", "ssh_bruteforce_success",
                             ip=login["ip"], user=login["user"], time=login["time"]))
        elif login["first_time"]:
            recs.append(_rec(f"ssh_new_ip:{login['ip']}", "medium", "ssh_new_ip", ip=login["ip"],
                             country=login["country"], user=login["user"], method=method, time=login["time"]))
    for ev in s["sensitive"]:
        recs.append(_rec(f"sensitive:{ev['target']}", "critical", "sensitive", target=ev["target"], ip=ev["ip"],
                         status=ev["status"], time=ev["time"]))
    banned = s["kinds"].get("f2b_ban", 0)
    if s["ssh_attack_conns"] >= 100 and banned == 0 and not any(f["code"] == "no_fail2ban" for f in s["findings"]):
        recs.append(_rec("f2b_silent", "medium", "f2b_silent", count=s["ssh_attack_conns"]))
    heavy = [ip for ip in s["top_ips"] if ip["count"] >= settings.spike_threshold and not ip["banned"]]
    if heavy:
        recs.append(Finding(
            "heavy_ips", "low", t("rec.heavy_ips.title", count=len(heavy)),
            ", ".join(f"{ip['ip']} ({ip['count']})" for ip in heavy[:5]), t("rec.heavy_ips.fix")))
    if s["kinds"].get("web_exploit"):
        recs.append(_rec("web_exploits", "low", "web_exploits", count=s["kinds"]["web_exploit"]))
    return recs


def system_recommendations(s: dict) -> list[Finding]:
    recs: list[Finding] = []
    by_kind: dict[str, list[dict]] = {}
    for ev in s["system_events"]:
        by_kind.setdefault(ev["kind"], []).append(ev)
    for ev in by_kind.get("sys_user_change", []):
        recs.append(_rec(f"sys_user_change:{ev['target']}:{ev['time']}", ev["severity"], "sys_user_change",
                         target=ev["target"], detail=ev["detail"], time=ev["time"]))
    if "sys_disk_error" in by_kind:
        recs.append(_rec("sys_disk_error", "high", "sys_disk_error", n=len(by_kind["sys_disk_error"])))
    if "sys_oom" in by_kind:
        names = sorted({e["target"] for e in by_kind["sys_oom"]})
        recs.append(_rec("sys_oom", "medium", "sys_oom", n=len(by_kind["sys_oom"]), targets=", ".join(names[:5])))
    for unit in sorted({e["target"] for e in by_kind.get("sys_service_failed", [])}):
        n = sum(1 for e in by_kind["sys_service_failed"] if e["target"] == unit)
        recs.append(_rec(f"sys_service_failed:{unit}", "medium", "sys_service_failed", unit=unit, n=n))
    if "sys_boot" in by_kind:
        recs.append(_rec("sys_boot", "info", "sys_boot", n=len(by_kind["sys_boot"]),
                         time=by_kind["sys_boot"][0]["time"]))
    if s["new_log_events"]:
        recs.append(_rec("new_log_events", "low", "new_log_events", n=len(s["new_log_events"])))
    return recs


def risk(recs: list[Finding], attacks: int) -> dict:
    score = min(100, sum(SEVERITY_POINTS.get(r.severity, 0) for r in recs) + (5 if attacks else 0))
    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 15:
        level = "medium"
    else:
        level = "low"
    return {"score": score, "level": level, "level_ru": severity_label(level, "ru"), "level_label": severity_label(level)}


def build_summary(settings: Settings, day: date | None = None, geo: Geo | None = None) -> dict:
    tz = ZoneInfo(settings.timezone)
    day = day or datetime.now(tz).date()
    start, end = day_bounds(day, tz)
    a, b = db.iso(start), db.iso(end)
    geo = geo or Geo.for_settings(settings)
    al = allowlist.load(settings)

    def local(ts: str) -> str:
        return datetime.fromisoformat(ts).astimezone(tz).strftime("%H:%M:%S")

    with db.connect(settings.db_path) as conn:
        kinds = {r["kind"]: r["n"] for r in _rows(
            conn, "select kind, count(*) n from events where ts >= ? and ts < ? and allowed = 0 group by kind", a, b)}
        attacks = sum(kinds.get(k, 0) for k in ATTACK_KINDS)
        ssh_conns = conn.execute(
            f"select count(distinct coalesce(conn || ip, id)) from events where ts >= ? and ts < ? and allowed = 0 "
            f"and kind in {_in(SSH_FAIL_KINDS)}", (a, b)).fetchone()[0]
        attacker_ips = conn.execute(
            f"select count(distinct ip) from events where ts >= ? and ts < ? and allowed = 0 and kind in {_in(ATTACK_KINDS)}",
            (a, b)).fetchone()[0]
        hours = Counter()
        for r in _rows(conn, f"select ts from events where ts >= ? and ts < ? and allowed = 0 and kind in {_in(ATTACK_KINDS)}", a, b):
            hours[datetime.fromisoformat(r["ts"]).astimezone(tz).hour] += 1
        banned_ips = {r["ip"] for r in _rows(conn, "select distinct ip from events where kind = 'f2b_ban'")}
        top_ips = []
        for r in _rows(conn,
                       f"select ip, count(*) n, min(ts) first, max(ts) last, group_concat(distinct kind) kinds "
                       f"from events where ts >= ? and ts < ? and allowed = 0 and kind in {_in(ATTACK_KINDS)} and ip is not null "
                       f"group by ip order by n desc limit 20", a, b):
            g = geo.lookup(r["ip"])
            top_ips.append({"ip": r["ip"], "count": r["n"], "first": local(r["first"]), "last": local(r["last"]),
                            "kinds": [kind_label(k) for k in sorted(r["kinds"].split(","))],
                            "country": g["country"], "asn": g["asn"], "banned": r["ip"] in banned_ips})
        usernames = _rows(conn,
                          "select username, count(*) n from events where ts >= ? and ts < ? and allowed = 0 and username is not null "
                          "and kind in ('ssh_failed_password','ssh_invalid_user','ssh_preauth_fail') "
                          "group by username order by n desc limit 15", a, b)
        web_targets = _rows(conn,
                            f"select target, count(*) n, count(distinct ip) ips, group_concat(distinct detail) labels, "
                            f"max(status) status from events where ts >= ? and ts < ? and allowed = 0 and kind in {_in(WEB_ATTACK_KINDS)} "
                            f"and target is not null group by target order by n desc limit 15", a, b)
        failed_ips = {r["ip"] for r in _rows(
            conn, f"select distinct ip from events where ts >= ? and ts < ? and allowed = 0 and kind in {_in(SSH_FAIL_KINDS)}", a, b)}
        ssh_logins = []
        for r in _rows(conn, "select ts, ip, username, detail from events where ts >= ? and ts < ? "
                             "and kind = 'ssh_accepted' order by ts", a, b):
            prior = conn.execute("select 1 from events where kind = 'ssh_accepted' and ip = ? and ts < ? limit 1",
                                 (r["ip"], a)).fetchone()
            method = (r["detail"] or "").split(" ")[0].replace("method=", "") or None
            ssh_logins.append({"time": local(r["ts"]), "ip": r["ip"], "user": r["username"], "method": method,
                               "country": geo.lookup(r["ip"])["country"], "had_failures": r["ip"] in failed_ips,
                               "first_time": prior is None, "known": al.match(r["ip"])})
        sensitive = [{**r, "time": local(r["ts"])} for r in _rows(
            conn, "select ts, ip, target, status from events where ts >= ? and ts < ? "
                  "and kind = 'web_sensitive_served' order by ts", a, b)]
        traffic = conn.execute("select coalesce(sum(total), 0) from traffic where hour >= ? and hour < ?",
                               (start.strftime("%Y-%m-%dT%H"), end.strftime("%Y-%m-%dT%H"))).fetchone()[0]
        trend = []
        for i in range(6, -1, -1):
            d = day - timedelta(days=i)
            s0, e0 = day_bounds(d, tz)
            n = conn.execute(f"select count(*) from events where ts >= ? and ts < ? and allowed = 0 and kind in {_in(ATTACK_KINDS)}",
                             (db.iso(s0), db.iso(e0))).fetchone()[0]
            trend.append({"day": d.isoformat(), "label": d.strftime("%d.%m"), "count": n})
        system_events = [{**r, "time": local(r["ts"]), "label": kind_label(r["kind"])} for r in _rows(
            conn, f"select ts, kind, target, detail, severity from events where ts >= ? and ts < ? "
                  f"and kind in {_in(SYSTEM_KINDS)} order by ts desc limit 50", a, b)]
        new_log_events = [{**r, "time": local(r["first_seen"])} for r in new_templates(conn, a, b)]
        findings = _rows(conn, "select source, code, severity, title, detail, fix, seen from findings")
        last_collect = db.get_meta(conn, "last_collect")

    s = {
        "day": day.isoformat(), "timezone": settings.timezone, "kinds": kinds, "attacks": attacks,
        "ssh_attack_conns": ssh_conns, "attacker_ips": attacker_ips, "web_requests": traffic,
        "web_attacks": sum(kinds.get(k, 0) for k in WEB_ATTACK_KINDS), "bans": kinds.get("f2b_ban", 0),
        "hours": [hours.get(h, 0) for h in range(24)], "top_ips": top_ips, "usernames": usernames,
        "web_targets": web_targets, "ssh_logins": ssh_logins, "sensitive": sensitive, "trend": trend,
        "findings": findings, "geo_available": geo.available, "geo_dbip": geo.attribution_dbip, "last_collect": last_collect,
        "supabase_enabled": settings.supabase_enabled, "telegram_enabled": settings.telegram_enabled,
        "system_events": system_events, "new_log_events": new_log_events, "allowlist_size": len(al),
    }
    recs = [Finding(f["code"], f["severity"], f["title"], f["detail"], f["fix"]) for f in findings
            if f["severity"] != "info"]
    recs += activity_recommendations(s, settings)
    recs += system_recommendations(s)
    recs.sort(key=lambda r: -SEVERITY_ORDER.get(r.severity, 0))
    s["recommendations"] = [{**r.__dict__, "severity_ru": severity_label(r.severity, "ru"),
                             "severity_label": severity_label(r.severity)} for r in recs]
    s["notes"] = [{**f, "severity_ru": severity_label("info", "ru"), "severity_label": severity_label("info")}
                  for f in findings if f["severity"] == "info"]
    s["risk"] = risk(recs, attacks)
    s["kind_rows"] = [{"kind": k, "label": kind_label(k), "count": n, "explain": kind_explanation(k)}
                      for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])]
    return s
