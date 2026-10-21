import os
from datetime import timedelta

import httpx
from fastapi.testclient import TestClient

from secwatch import db
from secwatch.alerts import ErpSender, Telegram, check_alerts, compact_summary, format_digest
from secwatch.audit import audit_host, read_sshd_config
from secwatch.collector import collect_logs
from secwatch.geo import Geo
from secwatch.summary import build_summary
from secwatch.supabase import classify_auth_log, fetch_advisors
from secwatch.web import create_app
from secwatch.worker import run_once


class Recorder(Telegram):
    def __init__(self, settings):
        super().__init__(settings)
        self.messages = []

    def send(self, text, category="digest"):
        self.messages.append((category, text))
        return True


def count(settings, sql="select count(*) from events"):
    with db.connect(settings.db_path) as conn:
        return conn.execute(sql).fetchone()[0]


def test_collect_is_incremental_and_handles_rotation(settings, host):
    first = collect_logs(settings)
    total = count(settings)
    assert total > 100 and sum(first.values()) == total
    assert sum(collect_logs(settings).values()) == 0  # nothing new
    auth = host / "var/log/auth.log"
    with open(auth, "a", encoding="utf-8") as fh:
        fh.write("2026-10-20T10:00:00+00:00 erp sshd[1]: Invalid user zz from 203.0.113.250 port 1\n")
        fh.write("partial line without newline")
    collect_logs(settings)
    assert count(settings) == total + 1  # the partial line waits for its newline
    os.replace(auth, str(auth) + ".1")  # rotation: new inode
    auth.write_text("2026-10-20T10:00:01+00:00 erp sshd[2]: Invalid user yy from 203.0.113.251 port 1\n")
    collect_logs(settings)
    assert count(settings) == total + 2



def test_copytruncate_rotation_keeps_new_events(settings, host):
    collect_logs(settings)
    auth = host / "var/log/auth.log"
    first = "2026-10-20T10:00:00+00:00 erp sshd[1]: Invalid user aa from 203.0.113.240 port 1\n"
    auth.write_text(first)                     # logrotate copytruncate: same inode, shorter file
    collect_logs(settings)
    before = count(settings)
    auth.write_text("2026-10-20T11:00:00+00:00 erp sshd[2]: Invalid user bb from 203.0.113.241 port 1\n")
    collect_logs(settings)                      # same offset 0, different line -> a new event
    assert count(settings) == before + 1
    assert count(settings, "select count(*) from events where ip = '203.0.113.241'") == 1


def test_secrets_never_stored(settings):
    collect_logs(settings)
    assert count(settings, "select count(*) from events where target like '%SECRET%' or detail like '%SECRET%'") == 0


def test_sshd_include_first_value_wins(settings):
    cfg = read_sshd_config(settings)
    assert cfg["passwordauthentication"] == "yes"  # from 50-cloud-init.conf via Include
    codes = {f.code for f in audit_host(settings)}
    assert {"ssh_password_auth", "ssh_x11", "ssh_root_key"} <= codes
    assert "no_fail2ban" not in codes and "ufw_disabled" not in codes
    hardening = settings.host_path("/etc/ssh/sshd_config.d/00-hardening.conf")
    with open(hardening, "w") as fh:
        fh.write("PasswordAuthentication no\n")
    assert "ssh_password_auth" not in {f.code for f in audit_host(settings)}


def test_summary_and_recommendations(settings):
    geo = Geo("", "")
    run_once(settings, Recorder(settings), geo, False)
    s = build_summary(settings, geo=geo)
    assert s["attacks"] > 50 and s["attacker_ips"] > 5 and s["web_requests"] > 100
    codes = [r["code"] for r in s["recommendations"]]
    assert any(c.startswith("ssh_bruteforce_success:203.0.113.66") for c in codes)
    assert any(c.startswith("sensitive:GET /.env") for c in codes)
    assert "ssh_password_auth" in codes
    assert s["recommendations"][0]["severity"] == "critical"
    assert s["risk"]["level"] == "critical"
    assert any(u["username"] == "admin" for u in s["usernames"])
    assert len(s["trend"]) == 7 and sum(s["hours"]) <= s["attacks"]
    assert "Что исправить" in format_digest(s)


def test_alerts_baseline_then_new_events(settings, host):
    sender = Recorder(settings)
    geo = Geo("", "")
    collect_logs(settings)
    assert check_alerts(settings, sender, geo) == []  # first run = baseline, no storm
    now = db.utc_now()
    lines = [f"{(now - timedelta(seconds=60 - i)).isoformat()} erp sshd[{9000 + i}]: Invalid user x{i} from 203.0.113.200 port {i}"
             for i in range(35)]
    lines.append(f"{now.isoformat()} erp sshd[9999]: Accepted publickey for root from 198.51.100.200 port 2 ssh2")
    with open(host / "var/log/auth.log", "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    collect_logs(settings)
    sent = check_alerts(settings, sender, geo, now=now)
    assert any("нового IP" in m and "198.51.100.200" in m for m in sent)
    assert any("Всплеск" in m and "203.0.113.200" in m for m in sent)
    assert any("Сводка" in m for m in sent) == (now.hour >= settings.digest_hour)
    again = check_alerts(settings, sender, geo, now=now)
    assert not any("нового IP" in m or "Всплеск" in m for m in again)
    categories = {c for c, _ in sender.messages}
    assert {"new_login", "spike"} <= categories


def test_new_critical_finding_alert(settings):
    sender = Recorder(settings)
    geo = Geo("", "")
    run_once(settings, sender, geo, False)  # baseline: existing findings are not alerted
    assert not any(c == "findings" for c, _ in sender.messages)
    with db.connect(settings.db_path) as conn:
        conn.execute("insert into findings (source, code, severity, title, detail, fix, seen) "
                     "values ('host', 'new_crit', 'critical', 'Something bad', 'detail', '', 'now')")
    check_alerts(settings, sender, geo)
    assert [c for c, _ in sender.messages].count("findings") == 1
    check_alerts(settings, sender, geo)
    assert [c for c, _ in sender.messages].count("findings") == 1


def test_erp_sender(settings):
    seen = []

    def handler(request: httpx.Request):
        seen.append((request.headers.get("authorization"), request.read()))
        return httpx.Response(200, json={"delivered": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    erp = ErpSender(settings, client)
    assert not erp.send("x", "spike")  # no key configured -> nothing sent
    settings.erp_ingest_key = "swk_test"
    assert not erp.send("x", "spike")  # key without a URL -> nothing sent
    settings.erp_ingest_url = "http://127.0.0.1:3000/api/security/ingest"
    assert erp.send("hello", "spike")
    run_once(settings, Recorder(settings), Geo("", ""), False)
    assert erp.push_summary(build_summary(settings, geo=Geo("", "")))
    import json
    auth, body = seen[0]
    assert auth == "Bearer swk_test" and json.loads(body) == {"type": "alert", "category": "spike", "text": "hello"}
    summary = json.loads(seen[1][1])["summary"]
    assert summary["risk_level"] == "critical" and len(summary["hours"]) == 24
    assert set(summary) == set(compact_summary(build_summary(settings, geo=Geo("", ""))))


def test_web_requires_password(settings):
    run_once(settings, Recorder(settings), Geo("", ""), False)
    client = TestClient(create_app(settings))
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("admin", "wrong")).status_code == 401
    r = client.get("/", auth=("admin", "test-password"))
    assert r.status_code == 200 and "Что исправить" in r.text and "203.0.113.66" in r.text
    assert r.headers["x-frame-options"] == "DENY"
    j = client.get("/api/summary", auth=("admin", "test-password")).json()
    assert j["risk"]["level"] == "critical"
    assert client.get("/?day=bad", auth=("admin", "test-password")).status_code == 400


def test_app_refuses_to_start_without_password(settings):
    settings.web_password = ""
    try:
        create_app(settings)
    except RuntimeError:
        return
    raise AssertionError("must refuse to start without a password")


def test_supabase_parsing(settings):
    assert classify_auth_log('{"msg":"Invalid login credentials","status":400,"path":"/token","remote_addr":"203.0.113.1"}') \
        == ("supabase_auth_fail", "203.0.113.1", "/token")
    assert classify_auth_log('{"status":429,"path":"/otp"}')[0] == "supabase_rate_limit"
    assert classify_auth_log('{"msg":"request completed","status":200}') is None

    def handler(request: httpx.Request):
        assert request.headers["authorization"] == "Bearer sbp_test"
        return httpx.Response(200, json={"lints": [{"name": "rls_disabled_in_public", "title": "RLS Disabled in Public",
                                                    "level": "ERROR", "detail": "Table public.x", "remediation": "https://x",
                                                    "metadata": {"schema": "public", "name": "x"}}]})
    settings.supabase_token, settings.supabase_project_ref = "sbp_test", "ref"
    client = httpx.Client(base_url="https://api.supabase.com", transport=httpx.MockTransport(handler),
                          headers={"Authorization": "Bearer sbp_test"})
    f = fetch_advisors(settings, client)
    assert f[0].severity == "high" and "public.x" in f[0].title


def test_supabase_auth_logs_from_unified_logs_endpoint(settings):
    from secwatch.supabase import fetch_auth_events, poll_supabase
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        if request.url.path.endswith("/advisors/security"):
            return httpx.Response(200, json={"lints": []})
        assert request.url.path == "/v1/projects/ref/analytics/endpoints/logs"
        q = request.url.params
        assert "source = 'auth_logs'" in q["sql"] and "like '4%'" in q["sql"]
        assert q["iso_timestamp_start"].endswith("Z") and "." not in q["iso_timestamp_start"]
        return httpx.Response(200, json={"result": [
            {"id": "a1", "timestamp": "2026-10-20T17:59:06.000000", "status": "400", "path": "/token",
             "ip": "203.0.113.9", "msg": "Invalid login credentials"},
            {"id": "a2", "timestamp": "2026-10-20T17:59:06.000000", "status": "400", "path": "/token",
             "ip": "203.0.113.9", "msg": "Invalid login credentials"},
            {"id": "a3", "timestamp": "2026-10-20T17:59:07.000000", "status": "429", "path": "/otp",
             "ip": "203.0.113.10", "msg": "request completed"},
            {"id": "a4", "timestamp": "2026-10-20T17:59:08.000000", "status": "404", "path": "/user",
             "ip": "203.0.113.11", "msg": "request completed"},
        ]})

    settings.supabase_token, settings.supabase_project_ref = "sbp_test", "ref"
    client = httpx.Client(base_url="https://api.supabase.com", transport=httpx.MockTransport(handler))
    items = fetch_auth_events(settings, client)
    assert [e.kind for _, e in items] == ["supabase_auth_fail", "supabase_auth_fail", "supabase_rate_limit"]
    assert len({k for k, _ in items}) == 3  # same second, different log ids -> not deduplicated away
    assert items[0][1].ts.tzinfo is not None and items[0][1].ip == "203.0.113.9"


def test_supabase_rejected_token_becomes_a_finding(settings, monkeypatch):
    from secwatch import supabase

    def handler(request: httpx.Request):
        return httpx.Response(401, json={"message": "Unauthorized"})

    settings.supabase_token, settings.supabase_project_ref = "sbp_expired", "ref"
    monkeypatch.setattr(supabase, "_client", lambda s: httpx.Client(base_url="https://api.supabase.com",
                                                                   transport=httpx.MockTransport(handler)))
    supabase.poll_supabase(settings)
    with db.connect(settings.db_path) as conn:
        codes = {r[0] for r in conn.execute("select code from findings where source = 'supabase'")}
    assert codes == {"supabase_token:advisors", "supabase_token:auth_logs"}


def test_supabase_advisors_grouped_per_lint(settings):
    from secwatch.supabase import fetch_advisors

    lints = [{"name": "rls_enabled_no_policy", "title": "RLS Enabled No Policy", "level": "INFO",
              "detail": f"Table public.t{i} has RLS enabled, but no policies", "description": "RLS without policies.",
              "metadata": {"schema": "public", "name": f"t{i:02d}"}} for i in range(40)]
    lints.append({"name": "auth_leaked_password_protection", "title": "Leaked Password Protection Disabled",
                  "level": "WARN", "detail": "off", "metadata": {}})

    def handler(request):
        return httpx.Response(200, json={"lints": lints})
    settings.supabase_token, settings.supabase_project_ref = "sbp_test", "ref"
    client = httpx.Client(base_url="https://api.supabase.com", transport=httpx.MockTransport(handler))
    found = {f.code: f for f in fetch_advisors(settings, client)}
    assert set(found) == {"supabase:rls_enabled_no_policy", "supabase:auth_leaked_password_protection"}
    rls = found["supabase:rls_enabled_no_policy"]
    assert rls.severity == "low" and "40 объектов" in rls.title and "public.t00" in rls.detail and "ещё 25" in rls.detail
    assert found["supabase:auth_leaked_password_protection"].severity == "medium"
    from secwatch.i18n import plural
    assert [plural(n, "plural.object") for n in (1, 2, 5, 11, 21, 22, 92, 112)] == [
        "объект", "объекта", "объектов", "объектов", "объект", "объекта", "объекта", "объектов"]


def test_old_database_gets_the_cursor_fingerprint_column(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as conn:
        conn.execute("create table cursors (path text primary key, inode integer, offset integer, updated text)")
        conn.execute("insert into cursors values ('/var/log/auth.log', 1, 10, 'x')")
    db.init_db(path)
    db.init_db(path)  # idempotent
    with db.connect(path) as conn:
        cols = {r["name"] for r in conn.execute("pragma table_info(cursors)")}
        assert "head" in cols and conn.execute("select offset from cursors").fetchone()[0] == 10
