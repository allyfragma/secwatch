"""Line parsers for sshd (auth.log), nginx access log and fail2ban log.

Each parser returns an Event or None. Nothing secret is stored: web query
strings are dropped (only the matched attack label is kept), SSH lines keep
user name, IP and port only.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .i18n import t
from .models import Event

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(?P<host>\S+)\s+(?P<rest>.*)$")
BSD_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<rest>.*)$")


def parse_syslog_ts(line: str, tz: ZoneInfo, now: datetime | None = None) -> tuple[datetime, str] | None:
    """Return (UTC timestamp, rest-of-line after host) for ISO or classic BSD syslog lines."""
    m = ISO_RE.match(line)
    if m:
        raw = m.group("ts").replace("Z", "+00:00")
        raw = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", raw)
        ts = datetime.fromisoformat(raw)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=tz)
        return ts.astimezone(timezone.utc), m.group("rest")
    m = BSD_RE.match(line)
    if m and m.group("mon") in MONTHS:
        now = now or datetime.now(timezone.utc)
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        year = now.astimezone(tz).year
        ts = datetime(year, MONTHS[m.group("mon")], int(m.group("day")), hh, mm, ss, tzinfo=tz)
        if ts - now > timedelta(days=1):  # December lines read in January
            ts = ts.replace(year=year - 1)
        return ts.astimezone(timezone.utc), m.group("rest")
    return None


# ---------------------------------------------------------------- sshd ---

SSH_PROG_RE = re.compile(r"^(?P<prog>sshd(?:-session)?)\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$")
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
SSH_RULES = [
    ("ssh_accepted", "notice",
     re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from " + _IP + r" port (?P<port>\d+)")),
    ("ssh_failed_password", "low",
     re.compile(r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?"
                r"(?P<user>\S*) from " + _IP + r" port (?P<port>\d+)")),
    ("ssh_failed_password", "low",
     re.compile(r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) from " + _IP)),
    ("ssh_invalid_user", "low",
     re.compile(r"^Invalid user (?P<user>.*?) from " + _IP + r"(?: port \d+)?\s*$")),
    ("ssh_preauth_fail", "info",
     re.compile(r"^(?:Connection (?:closed|reset) by|Disconnected from) (?:(?:authenticating|invalid) user "
                r"(?P<user>\S*) )?" + _IP + r" port \d+\s*\[preauth\]")),
    ("ssh_preauth_fail", "info",
     re.compile(r"^Received disconnect from " + _IP + r" port \d+:\d+: .*\[preauth\]")),
    ("ssh_probe", "info",
     re.compile(r"^(?:Unable to negotiate with |banner exchange: Connection from )" + _IP + r" port \d+")),
]


def parse_ssh(line: str, tz: ZoneInfo, now: datetime | None = None) -> Event | None:
    head = parse_syslog_ts(line, tz, now)
    if not head:
        return None
    ts, rest = head
    pm = SSH_PROG_RE.match(rest)
    if not pm:
        return None
    msg = pm.group("msg")
    for kind, severity, rx in SSH_RULES:
        m = rx.match(msg)
        if not m:
            continue
        g = m.groupdict()
        detail = None
        if g.get("method"):
            detail = f"method={g['method']}"
        if g.get("port"):
            detail = (detail + " " if detail else "") + f"port={g['port']}"
        return Event(ts=ts, source="ssh", kind=kind, ip=g.get("ip"), username=g.get("user") or None,
                     target="ssh", conn=f"sshd:{pm.group('pid')}", detail=detail, severity=severity)
    return None


# ---------------------------------------------------------------- nginx ---

NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')
REQ_RE = re.compile(r"^(?P<method>[A-Z]{3,10}) (?P<url>\S+)(?: HTTP/\d(?:\.\d)?)?$")

SCAN_PATTERNS = [re.compile(p) for p in (
    r"/\.env", r"/\.git(/|$)", r"/\.svn", r"/\.hg", r"/\.aws", r"/\.ssh", r"/\.ds_store", r"/\.vscode", r"/\.idea",
    r"wp-login\.php", r"/wp-admin", r"/wp-content", r"/wp-includes", r"xmlrpc\.php", r"/wordpress",
    r"phpmyadmin", r"/pma(/|$)", r"/myadmin", r"/adminer", r"phpunit", r"eval-stdin\.php", r"/vendor/",
    r"/cgi-bin/", r"/boaform", r"/hnap1", r"/actuator", r"/server-status", r"/server-info",
    r"/config\.(?:json|php|yml|yaml|js)$", r"/backup", r"\.sql(?:\.gz|\.zip)?$", r"\.bak$", r"\.old$", r"\.swp$",
    r"/admin\.php", r"/shell", r"/manager/html", r"/solr/", r"/owa/", r"/autodiscover", r"/telescope",
    r"/_profiler", r"/sftp-config\.json", r"/debug/default/view", r"/containers/json", r"/api/v1/pods",
    r"/druid/", r"/geoserver", r"/console(/|$)", r"/remote/login", r"/sdk$", r"/ecp/", r"/\.well-known/security\.txt\.bak",
    r"/info\.php", r"/phpinfo", r"/test\.php", r"/setup\.php", r"/install\.php", r"/laravel", r"/storage/logs",
)]
SENSITIVE_PATTERNS = [re.compile(p) for p in (
    r"/\.env", r"/\.git/", r"/\.aws", r"/\.ssh", r"\.sql(?:\.gz|\.zip)?$", r"\.bak$", r"/backup", r"/config\.(?:json|php|yml|yaml)$",
    r"/storage/logs", r"/sftp-config\.json",
)]
# Labels are catalog keys (parser.exploit.*), resolved when an event is built.
EXPLOIT_PATTERNS = [(re.compile(p), label) for p, label in (
    (r"\.\./|%2e%2e(?:/|%2f)|\.\.%2f", "path_traversal"),
    (r"union(?:\s|%20|\+|/\*\*/)+(?:all(?:\s|%20|\+)+)?select|'(?:\s|%20|\+)*or(?:\s|%20|\+)+1=1|sleep\(\d", "sql_injection"),
    (r"<script|%3cscript|javascript:|onerror=", "xss"),
    (r"\$\{jndi:|%24%7bjndi", "log4shell"),
    (r"/etc/passwd|/proc/self/environ|win\.ini", "system_files"),
    (r"(?:;|%3b|\|)\s*(?:wget|curl|bash|sh|nc)(?:\s|%20|\+)|\$\((?:wget|curl)", "command_injection"),
    (r"allow_url_include|auto_prepend_file|php://input", "php_injection"),
    (r"/\?xdebug_session_start|/index\.php\?s=/index/\\think", "framework"),
)]
SCANNER_UA = ("sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "gobuster", "dirbuster", "wpscan",
              "feroxbuster", "fuzz faster", "ffuf", "censysinspect", "l9explore", "l9tcpid", "expanse",
              "internet-measurement", "odin.io", "netcraft", "acunetix", "openvas", "whatweb", "jaeles", "dirsearch")


def parse_nginx_time(raw: str) -> datetime:
    return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)


def parse_nginx(line: str) -> tuple[datetime | None, Event | None]:
    """Return (timestamp of the request or None if unparsable, attack event or None)."""
    m = NGINX_RE.match(line)
    if not m:
        return None, None
    try:
        ts = parse_nginx_time(m.group("time"))
    except ValueError:
        return None, None
    ip, status, req = m.group("ip"), int(m.group("status")), m.group("req")
    ua = (m.group("ua") or "").lower()
    size = m.group("size")
    rm = REQ_RE.match(req)
    if not rm:
        # TLS handshake on the HTTP port, binary noise, empty request "-".
        return ts, Event(ts=ts, source="nginx", kind="web_probe", ip=ip, status=status,
                         target=None, detail=t("parser.malformed"), severity="info")
    method, url = rm.group("method"), rm.group("url")
    url_l = url.lower()
    path = url.split("?", 1)[0][:200]
    target = f"{method} {path}"
    for rx, label in EXPLOIT_PATTERNS:
        if rx.search(url_l):
            return ts, Event(ts=ts, source="nginx", kind="web_exploit", ip=ip, status=status, target=target,
                             detail=t(f"parser.exploit.{label}"), severity="medium")
    path_l = path.lower()
    if any(rx.search(path_l) for rx in SCAN_PATTERNS):
        served = 200 <= status < 300 and size not in ("0", "-")
        if served and any(rx.search(path_l) for rx in SENSITIVE_PATTERNS):
            return ts, Event(ts=ts, source="nginx", kind="web_sensitive_served", ip=ip, status=status, target=target,
                             detail=t("parser.served", status=status, size=size), severity="critical")
        return ts, Event(ts=ts, source="nginx", kind="web_scan", ip=ip, status=status, target=target,
                         severity="low")
    if any(s in ua for s in SCANNER_UA):
        return ts, Event(ts=ts, source="nginx", kind="web_scanner", ip=ip, status=status, target=target,
                         detail=next(s for s in SCANNER_UA if s in ua), severity="low")
    if status == 401 or (status == 403 and any(w in path_l for w in ("login", "auth", "signin", "token"))):
        return ts, Event(ts=ts, source="nginx", kind="web_auth_fail", ip=ip, status=status, target=target,
                         severity="info")
    return ts, None


# ----------------------------------------------------------------- caddy ---
# Privacy-filtered Caddy JSON access log: no path, no headers, only
# ts, status, method (or OTHER), route_group (auth/api/assets/...), peer_ip.


def parse_caddy(line: str) -> tuple[datetime | None, Event | None]:
    import json

    try:
        d = json.loads(line)
    except ValueError:
        return None, None
    if not isinstance(d, dict) or "ts" not in d or "status" not in d:
        return None, None
    try:
        ts = datetime.fromtimestamp(float(d["ts"]), timezone.utc)
        status = int(d["status"])
    except (TypeError, ValueError):
        return None, None
    ip = d.get("peer_ip") or None
    method = str(d.get("method") or "?")
    group = str(d.get("route_group") or "other")
    target = f"{method} [{group}]"

    def ev(kind: str, detail: str, severity: str = "low") -> Event:
        return Event(ts=ts, source="caddy", kind=kind, ip=ip, status=status, target=target,
                     detail=detail, severity=severity)

    if method == "OTHER":
        return ts, ev("web_probe", t("parser.caddy.other_method"), "info")
    if status in (400, 414, 431, 444):
        return ts, ev("web_probe", t("parser.caddy.malformed", status=status), "info")
    if group == "auth" and status in (401, 403, 429):
        return ts, ev("web_auth_fail", t("parser.caddy.login_denied", status=status), "low")
    if status == 401:
        return ts, ev("web_auth_fail", "401", "info")
    if status == 429:
        return ts, ev("web_probe", t("parser.caddy.rate_limited"), "low")
    if status == 404 and group in ("other", "api"):
        return ts, ev("web_scan", t("parser.caddy.not_found"), "low")
    return ts, None


# ------------------------------------------------------------- fail2ban ---

F2B_RE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:,\d+)?\s+fail2ban\.actions\s+\[\d+\]:\s+\w+\s+"
    r"\[(?P<jail>[^\]]+)\]\s+(?P<action>Ban|Unban|Restore Ban)\s+(?P<ip>\S+)")


def parse_fail2ban(line: str, tz: ZoneInfo) -> Event | None:
    m = F2B_RE.match(line)
    if not m or m.group("action") == "Unban":
        return None
    ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz).astimezone(timezone.utc)
    return Event(ts=ts, source="fail2ban", kind="f2b_ban", ip=m.group("ip"), target=m.group("jail"),
                 detail=m.group("action"), severity="info")
