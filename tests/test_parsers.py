from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from secwatch.parsers import parse_caddy, parse_fail2ban, parse_nginx, parse_ssh

UTC = ZoneInfo("UTC")
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def ssh(msg, prog="sshd-session[123]"):
    return parse_ssh(f"2026-10-20T10:00:00.123456+00:00 erp {prog}: {msg}", UTC, NOW)


def test_ssh_kinds():
    assert ssh("Failed password for root from 203.0.113.5 port 5555 ssh2").kind == "ssh_failed_password"
    e = ssh("Failed password for invalid user admin from 203.0.113.5 port 5555 ssh2")
    assert (e.kind, e.username, e.ip) == ("ssh_failed_password", "admin", "203.0.113.5")
    assert ssh("Invalid user oracle from 203.0.113.6 port 1234").kind == "ssh_invalid_user"
    assert ssh("Connection closed by invalid user test 203.0.113.7 port 22 [preauth]").kind == "ssh_preauth_fail"
    assert ssh("Connection closed by authenticating user root 203.0.113.7 port 22 [preauth]").username == "root"
    assert ssh("Received disconnect from 203.0.113.8 port 40000:11: Bye Bye [preauth]").kind == "ssh_preauth_fail"
    assert ssh("Unable to negotiate with 203.0.113.9 port 4000: no matching key exchange method", "sshd[9]").kind == "ssh_probe"
    a = ssh("Accepted publickey for root from 198.51.100.7 port 51022 ssh2: ED25519 SHA256:x")
    assert (a.kind, a.username, a.detail) == ("ssh_accepted", "root", "method=publickey port=51022")
    assert ssh("Disconnected from user root 198.51.100.7 port 51022") is None  # normal logout
    assert ssh("Accepted publickey for root from 1.2.3.4 port 1", "cron[1]") is None


def test_ssh_ipv6_and_conn():
    e = ssh("Failed password for root from 2001:db8::1 port 5555 ssh2")
    assert e.ip == "2001:db8::1" and e.conn == "sshd:123"


def test_bsd_syslog_year_rollover():
    e = parse_ssh("Dec 31 23:59:59 erp sshd[1]: Invalid user x from 203.0.113.1 port 1", UTC,
                  datetime(2027, 1, 1, 0, 0, 30, tzinfo=timezone.utc))
    assert e.ts.year == 2026


def test_nginx_classification():
    line = '203.0.113.5 - - [20/Oct/2026:10:00:00 +0000] "GET {} HTTP/1.1" {} 150 "-" "{}"'
    ts, e = parse_nginx(line.format("/.env", 404, "Mozilla"))
    assert ts and e.kind == "web_scan" and e.target == "GET /.env"
    _, e = parse_nginx(line.format("/.env", 200, "Mozilla"))
    assert e.kind == "web_sensitive_served" and e.severity == "critical"
    _, e = parse_nginx(line.format("/x?q=1%27%20UNION%20SELECT%201", 400, "curl"))
    assert e.kind == "web_exploit" and e.detail == "SQL-инъекция"
    _, e = parse_nginx(line.format("/api/x?token=SECRET123", 401, "python"))
    assert e.kind == "web_auth_fail" and "SECRET" not in (e.target or "")
    _, e = parse_nginx(line.format("/", 200, "sqlmap/1.7"))
    assert e.kind == "web_scanner"
    ts, e = parse_nginx(line.format("/bookings", 200, "Mozilla"))
    assert ts is not None and e is None
    _, e = parse_nginx('203.0.113.5 - - [20/Oct/2026:10:00:00 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"')
    assert e.kind == "web_probe"


def test_caddy_privacy_filtered_log():
    base = '{{"level":"info","ts":1792500000.5,"logger":"http.log.access.site_security","msg":"handled request",' \
           '"bytes_read":0,"duration":0.01,"size":10,"status":{},"method":"{}","route_group":"{}","peer_ip":"203.0.113.5"}}'
    ts, e = parse_caddy(base.format(401, "POST", "auth"))
    assert ts.year == 2026 and e.kind == "web_auth_fail" and e.target == "POST [auth]" and e.severity == "low"
    assert parse_caddy(base.format(404, "GET", "other"))[1].kind == "web_scan"
    assert parse_caddy(base.format(200, "OTHER", "other"))[1].kind == "web_probe"
    assert parse_caddy(base.format(400, "GET", "api"))[1].kind == "web_probe"
    ts, e = parse_caddy(base.format(200, "GET", "assets"))
    assert ts is not None and e is None
    assert parse_caddy("not json") == (None, None)


def test_fail2ban():
    e = parse_fail2ban("2026-10-20 10:00:01,123 fail2ban.actions        [811]: NOTICE  [sshd] Ban 203.0.113.5", UTC)
    assert (e.kind, e.ip, e.target) == ("f2b_ban", "203.0.113.5", "sshd")
    assert parse_fail2ban("2026-10-20 10:00:01,123 fail2ban.actions [811]: NOTICE [sshd] Unban 203.0.113.5", UTC) is None
