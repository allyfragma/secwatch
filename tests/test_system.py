from datetime import datetime, timedelta, timezone

from secwatch import allowlist, db
from secwatch.alerts import check_alerts
from secwatch.collector import collect_logs
from secwatch.geo import Geo
from secwatch.summary import build_summary
from secwatch.syslograre import TemplateTracker, new_templates, notable_event, template
from tests.test_pipeline import Recorder, count

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------- allowlist ---

def test_allowlist_parse_and_match():
    al = allowlist.parse("203.0.113.5 office\n198.51.100.0/24\tVPN # comment\nnot-an-ip\n; 2001:db8::/32 v6")
    assert al.match("203.0.113.5") == "office" and al.match("198.51.100.77") == "VPN"
    assert al.match("2001:db8::1") == "v6" and al.match("192.0.2.1") is None and al.match("bad") is None
    assert al.errors == ["not-an-ip"] and len(al) == 3


def test_allowlisted_ip_is_not_an_attack_and_does_not_alert(settings, host):
    sender, geo = Recorder(settings), Geo("", "")
    collect_logs(settings)
    check_alerts(settings, sender, geo)  # baseline
    before = build_summary(settings, geo=geo)
    assert any(ip["ip"] == "203.0.113.66" for ip in before["top_ips"])

    settings.allowlist = "203.0.113.66 office; 198.51.100.200 laptop"
    now = db.utc_now()
    with open(host / "var/log/auth.log", "a", encoding="utf-8") as fh:
        fh.write(f"{now.isoformat()} erp sshd[9999]: Accepted publickey for root from 198.51.100.200 port 2 ssh2\n")
    from secwatch.worker import run_once
    run_once(settings, sender, geo, False)
    after = build_summary(settings, geo=geo)

    assert not any(ip["ip"] == "203.0.113.66" for ip in after["top_ips"])
    assert after["attacks"] < before["attacks"]
    assert not any("203.0.113.66" in r["code"] for r in after["recommendations"])  # brute-force-success gone
    login = next(l for l in after["ssh_logins"] if l["ip"] == "198.51.100.200")
    assert login["known"] == "laptop"
    assert not any(c == "new_login" for c, _ in sender.messages)
    assert after["allowlist_size"] == 2

    settings.allowlist = ""  # removing the entry brings the history back
    run_once(settings, sender, geo, False)
    assert any(ip["ip"] == "203.0.113.66" for ip in build_summary(settings, geo=geo)["top_ips"])


def test_invalid_allowlist_entries_become_a_finding(settings):
    settings.allowlist = "office-router"
    from secwatch.worker import run_once
    run_once(settings, Recorder(settings), Geo("", ""), False)
    assert count(settings, "select count(*) from findings where code = 'allowlist_invalid'") == 1


# ---------------------------------------------------------- rare events ---

def test_template_masks_values():
    a = template("[UFW BLOCK] IN=eth0 OUT= MAC=96:00:03:aa:bb:cc:d2:74:7f:6e:37:e3:08:00 SRC=203.0.113.9 DST=10.0.0.2 LEN=40 TTL=243 SPT=48211 DPT=3389")
    b = template("[UFW BLOCK] IN=eth0 OUT= MAC=96:00:03:aa:bb:cc:d2:74:7f:6e:37:e3:08:00 SRC=198.51.100.4 DST=10.0.0.2 LEN=44 TTL=50 SPT=1 DPT=22")
    assert a == b and "203.0.113.9" not in a
    assert template("Started session-4711.scope - Session 4711 of User root.") == \
        template("Started session-12.scope - Session 12 of User root.")
    assert "<email>" in template("mail to ops@example.com failed") and "<uuid>" in template(
        "id 123e4567-e89b-12d3-a456-426614174000")


def test_notable_events():
    ts = NOW
    oom = notable_event(ts, "kernel", "Out of memory: Killed process 1234 (node) total-vm:1kB")
    assert oom.kind == "sys_oom" and oom.target == "node"
    sudo = notable_event(ts, "usermod", "add 'mallory' to group 'sudo'")
    assert sudo.kind == "sys_user_change" and sudo.severity == "critical" and sudo.target == "mallory"
    staff = notable_event(ts, "gpasswd", "add 'ann' to group 'video'")
    assert staff.severity == "high"
    svc = notable_event(ts, "systemd", "nginx.service: Failed with result 'exit-code'.")
    assert svc.kind == "sys_service_failed" and svc.target == "nginx.service" and svc.detail == "exit-code"
    assert notable_event(ts, "kernel", "Linux version 6.8.0-45-generic (buildd@lcy02)").kind == "sys_boot"
    assert notable_event(ts, "kernel", "EXT4-fs error (device sda1): ext4_find_entry").kind == "sys_disk_error"
    assert notable_event(ts, "CRON", "(root) CMD (run-parts /etc/cron.hourly)") is None


def test_learning_then_new_kinds(settings):
    with db.connect(settings.db_path) as conn:
        tr = TemplateTracker()
        tr.observe(NOW, "CRON", "(root) CMD (backup 1)")
        assert tr.flush(conn, 3, NOW) == 0  # learning
        later = NOW + timedelta(days=4)
        tr.observe(later, "CRON", "(root) CMD (backup 2)")     # same template -> not new
        tr.observe(later, "dockerd", "API listen on 0.0.0.0:2375")
        assert tr.flush(conn, 3, later) == 1
        rows = new_templates(conn, db.iso(later - timedelta(hours=1)), db.iso(later + timedelta(hours=1)))
        assert [r["program"] for r in rows] == ["dockerd"] and "<ip>" in rows[0]["template"]
        assert conn.execute("select count from log_templates where program = 'CRON'").fetchone()[0] == 2


def test_syslog_and_auth_changes_end_to_end(settings, host):
    sender, geo = Recorder(settings), Geo("", "")
    collect_logs(settings)
    check_alerts(settings, sender, geo)  # baseline
    now = db.utc_now()
    (host / "var/log/syslog").write_text(
        f"{now.isoformat()} erp kernel: Out of memory: Killed process 77 (python3) total-vm:9kB\n"
        f"{now.isoformat()} erp systemd[1]: caddy.service: Failed with result 'signal'.\n")
    with open(host / "var/log/auth.log", "a", encoding="utf-8") as fh:
        fh.write(f"{now.isoformat()} erp usermod[555]: add 'mallory' to group 'sudo'\n")
    settings.syslog_logs = [str(host / "var/log/syslog")]
    from secwatch.worker import run_once
    run_once(settings, sender, geo, False)
    s = build_summary(settings, geo=geo)
    kinds = {e["kind"] for e in s["system_events"]}
    assert kinds == {"sys_oom", "sys_service_failed", "sys_user_change"}
    codes = [r["code"] for r in s["recommendations"]]
    assert any(c.startswith("sys_user_change:mallory") for c in codes) and "sys_oom" in codes
    assert s["recommendations"][0]["severity"] == "critical"
    alerts = [text for c, text in sender.messages if c == "findings"]
    assert any("mallory" in text for text in alerts)
    assert count(settings, "select count(*) from log_templates") > 0


def test_noise_reduction():
    ufw = ("[UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=203.0.113.9 DST=10.0.0.2 "
           "LEN=40 TOS=0x00 PREC=0x00 TTL=243 ID=54321 PROTO=TCP SPT=48211 DPT=3389 WINDOW=1024 RES=0x00 SYN URGP=0")
    assert template(ufw) == "[UFW BLOCK] PROTO=TCP"
    assert template("message repeated 3 times: [ [UFW BLOCK] IN=eth0 SRC=1.2.3.4 PROTO=UDP DPT=53]") == "[UFW BLOCK] PROTO=UDP"
    a = template('{"msg":"looking up info for HTTP challenge","uri":"/.well-known/acme-challenge/vKod-pTA9nTQAStn-uTmcPPK0Wx"}')
    b = template('{"msg":"looking up info for HTTP challenge","uri":"/.well-known/acme-challenge/Zq81-kLpQ2wX9m0aaBcDeFgH7u"}')
    assert a == b and "<id>" in a
    assert template("at 2026-10-21T08:40:32.12+00:00 and 12:01:02") == "at <time> and <time>"
    tracker = TemplateTracker()
    tracker.observe(NOW, "python", "2026-10-21 08:40:32,123 INFO secwatch.collector: ssh: 5 new events from /var/log/auth.log")
    assert tracker.seen == {}  # the monitor's own log lines are skipped
    assert notable_event(NOW, "usermod", "add 'secwatch' to shadow group 'adm'") is None


def test_units_and_ssh_are_not_new_kinds():
    assert template("Consumed 3.5s CPU time, 120M memory peak") == template("Consumed 12s CPU time, 4K memory peak")
    tracker = TemplateTracker()
    tracker.observe(NOW, "sshd", "Invalid user king from 203.0.113.4 port 22")
    assert tracker.seen == {}
