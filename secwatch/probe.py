"""`secwatch probe`: check a server from the OUTSIDE, the way an attacker sees it.

Run it from another machine (a scheduled GitHub Action is free and is
"outside" by definition). It checks:
- which risky TCP ports answer from the internet;
- the HTTPS certificate, the HTTP→HTTPS redirect and HSTS;
- whether secret files (.env, .git, backups, status pages) are served —
  decided by their CONTENT, so sites that answer 200 to every path do not
  cause false alarms;
- that API URLs you list refuse to answer without a login.

Only probe servers you own. It sends a few dozen ordinary requests, no
exploits, and never prints response bodies.
"""

from __future__ import annotations

import re
import socket
import ssl
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .i18n import t
from .models import SEVERITY_ORDER, Finding, catalog_finding

USER_AGENT = "secwatch-probe (+https://github.com/allyfragma/secwatch)"
DEFAULT_ALLOWED_PORTS = (22, 80, 443)

# Ports that should almost never be reachable from the internet, with what usually listens there.
RISKY_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "high"), 23: ("Telnet", "critical"), 445: ("SMB", "critical"),
    1433: ("MS SQL", "critical"), 2375: ("Docker API (no TLS)", "critical"), 2376: ("Docker API", "high"),
    3000: ("dev server / Node.js", "medium"), 3306: ("MySQL", "critical"), 3389: ("RDP", "high"),
    4000: ("dev server", "medium"), 5000: ("dev server / registry", "medium"), 5432: ("PostgreSQL", "critical"),
    5601: ("Kibana", "high"), 5900: ("VNC", "critical"), 6379: ("Redis", "critical"),
    8000: ("dev server", "medium"), 8080: ("HTTP alt / admin panel", "medium"), 8088: ("secwatch dashboard", "high"),
    8443: ("HTTPS alt / admin panel", "medium"), 8888: ("Jupyter", "critical"), 9000: ("admin panel / MinIO", "medium"),
    9090: ("Prometheus / Cockpit", "high"), 9200: ("Elasticsearch", "critical"), 11211: ("Memcached", "critical"),
    15672: ("RabbitMQ admin", "high"), 27017: ("MongoDB", "critical"), 54321: ("local Supabase API", "high"),
    54323: ("local Supabase Studio", "critical"),
}

# path -> (what it is, content check). A 200 alone proves nothing: SPAs answer 200 everywhere.
SECRET_PATHS: dict[str, tuple[str, Callable[[bytes], bool]]] = {
    "/.env": (".env with secrets", lambda b: bool(re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=\S", b)) and b"<html" not in b[:500].lower()),
    "/.env.production": (".env with secrets", lambda b: bool(re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=\S", b)) and b"<html" not in b[:500].lower()),
    "/.git/config": ("git repository", lambda b: b"[core]" in b),
    "/.git/HEAD": ("git repository", lambda b: b.startswith(b"ref: refs/") or bool(re.fullmatch(rb"[0-9a-f]{40}\s*", b))),
    "/.DS_Store": ("macOS folder index", lambda b: b[4:8] == b"Bud1"),
    "/backup.zip": ("backup archive", lambda b: b.startswith(b"PK\x03\x04")),
    "/backup.sql": ("database dump", lambda b: b"CREATE TABLE" in b or b"INSERT INTO" in b),
    "/dump.sql": ("database dump", lambda b: b"CREATE TABLE" in b or b"INSERT INTO" in b),
    "/docker-compose.yml": ("docker-compose file", lambda b: b"services:" in b and b"<html" not in b[:500].lower()),
    "/phpinfo.php": ("phpinfo page", lambda b: b"PHP Version" in b),
    "/server-status": ("Apache status page", lambda b: b"Apache Server Status" in b),
    "/actuator/env": ("Spring actuator", lambda b: b"propertySources" in b),
    "/wp-config.php.bak": ("WordPress config backup", lambda b: b"DB_PASSWORD" in b),
}


@dataclass
class ProbeConfig:
    targets: list[str]
    must_deny: list[str] = field(default_factory=list)
    allowed_ports: set[int] = field(default_factory=lambda: set(DEFAULT_ALLOWED_PORTS))
    timeout: float = 5.0


def parse_list(value: str | Iterable[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    items: list[str] = []
    for chunk in value:
        for line in str(chunk).splitlines():
            line = line.split("#", 1)[0] if line.lstrip().startswith("#") or " #" in line else line
            items += [v for v in re.split(r"[\s,]+", line) if v]
    return items


def normalize_target(target: str) -> str:
    return target if "://" in target else f"https://{target}"


# ----------------------------------------------------------------- checks ---

def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_ports(host: str, cfg: ProbeConfig, is_open: Callable[[str, int, float], bool] = port_open) -> list[Finding]:
    ports = [p for p in RISKY_PORTS if p not in cfg.allowed_ports]
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda p: (p, is_open(host, p, min(cfg.timeout, 3.0))), ports))
    out = []
    for port, opened in results:
        if opened:
            service, severity = RISKY_PORTS[port]
            out.append(catalog_finding(f"probe_port:{host}:{port}", severity, "probe_port",
                                       host=host, port=port, service=service))
    return out


def cert_days_left(host: str, port: int = 443, timeout: float = 5.0) -> int:
    """Days until the certificate expires; raises ssl.SSLError / OSError if invalid or unreachable."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            not_after = tls.getpeercert()["notAfter"]
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
    return (expires - datetime.now(timezone.utc)).days


def check_tls(host: str, cfg: ProbeConfig, days_left: Callable[..., int] = cert_days_left) -> list[Finding]:
    try:
        days = days_left(host, 443, cfg.timeout)
    except ssl.SSLCertVerificationError as exc:
        return [catalog_finding(f"probe_tls_invalid:{host}", "high", "probe_tls_invalid", host=host,
                                error=str(exc.verify_message or exc)[:120])]
    except (OSError, ssl.SSLError):
        return []  # no HTTPS on this host: reported by the HTTP checks if it matters
    if days < 3:
        return [catalog_finding(f"probe_tls_expiring:{host}", "high", "probe_tls_expiring", host=host, days=max(days, 0))]
    if days < 14:
        return [catalog_finding(f"probe_tls_expiring:{host}", "medium", "probe_tls_expiring", host=host, days=days)]
    return []


def check_http(base: str, client: httpx.Client) -> list[Finding]:
    out: list[Finding] = []
    parts = urlsplit(base)
    host = parts.hostname or base
    if parts.scheme == "https":
        try:
            r = client.get(f"http://{parts.netloc}/", follow_redirects=False)
            location = r.headers.get("location", "")
            if not (300 <= r.status_code < 400 and location.startswith("https://")):
                out.append(catalog_finding(f"probe_no_https_redirect:{host}", "low", "probe_no_https_redirect", host=host))
        except httpx.HTTPError:
            pass  # port 80 closed is fine
        try:
            r = client.get(base, follow_redirects=True)
            if "strict-transport-security" not in r.headers:
                out.append(catalog_finding(f"probe_no_hsts:{host}", "low", "probe_no_hsts", host=host))
        except httpx.HTTPError:
            out.append(catalog_finding(f"probe_unreachable:{host}", "medium", "probe_unreachable", url=base))
            return out
    for path, (what, looks_real) in SECRET_PATHS.items():
        url = base.rstrip("/") + path
        try:
            with client.stream("GET", url, follow_redirects=False) as r:
                if r.status_code != 200:
                    continue
                body = b""
                for chunk in r.iter_bytes():
                    body += chunk
                    if len(body) >= 65536:
                        break
        except httpx.HTTPError:
            continue
        if looks_real(body):
            out.append(catalog_finding(f"probe_secret_file:{url}", "critical", "probe_secret_file", url=url, what=what))
    return out


def check_must_deny(urls: list[str], client: httpx.Client) -> list[Finding]:
    out = []
    for url in urls:
        try:
            r = client.get(url, follow_redirects=False)
        except httpx.HTTPError:
            continue
        if 200 <= r.status_code < 300 and r.content.strip():
            out.append(catalog_finding(f"probe_api_open:{url}", "high", "probe_api_open", url=url,
                                       status=r.status_code, size=len(r.content)))
    return out


def run_probe(cfg: ProbeConfig, client: httpx.Client | None = None,
              is_open: Callable[[str, int, float], bool] = port_open,
              days_left: Callable[..., int] = cert_days_left) -> list[Finding]:
    own = client is None
    client = client or httpx.Client(timeout=cfg.timeout, headers={"User-Agent": USER_AGENT})
    findings: list[Finding] = []
    try:
        bases = [normalize_target(x) for x in cfg.targets]
        hosts = sorted({urlsplit(b).hostname for b in bases if urlsplit(b).hostname})
        for host in hosts:
            findings += check_ports(host, cfg, is_open)
            if any(urlsplit(b).scheme == "https" and urlsplit(b).hostname == host for b in bases):
                findings += check_tls(host, cfg, days_left)
        for base in bases:
            findings += check_http(base, client)
        findings += check_must_deny([normalize_target(u) for u in cfg.must_deny], client)
    finally:
        if own:
            client.close()
    findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    return findings


# ----------------------------------------------------------------- output ---

def format_report(findings: list[Finding], targets: list[str], html: bool = False) -> str:
    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") if html else s
    bold = (lambda s: f"<b>{esc(s)}</b>") if html else (lambda s: s)
    head = bold(t("probe.report.title", targets=", ".join(targets)))
    if not findings:
        return f"{head}\n✅ {esc(t('probe.report.ok'))}"
    lines = [head, esc(t("probe.report.found", n=len(findings)))]
    for f in findings:
        lines.append(f"\n[{f.severity}] {bold(f.title)}\n{esc(f.detail)}\n→ {esc(f.fix)}")
    return "\n".join(lines)


def send_telegram(token: str, chat_id: str, text: str, client: httpx.Client | None = None) -> bool:
    own = client is None
    client = client or httpx.Client(timeout=15)
    try:
        r = client.post(f"https://api.telegram.org/bot{token}/sendMessage",
                        json={"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML",
                              "disable_web_page_preview": True})
        return r.status_code == 200
    except httpx.HTTPError:  # never print the URL: it contains the token
        return False
    finally:
        if own:
            client.close()


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    limit = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])
    return any(SEVERITY_ORDER.get(f.severity, 0) >= limit for f in findings)
