import ssl

import httpx

from secwatch import i18n
from secwatch.__main__ import main
from secwatch.probe import ProbeConfig, format_report, parse_list, run_probe, should_fail

SPA = b"<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"


def site(routes: dict[str, httpx.Response], default=None):
    """Mock web server: exact URL -> response; anything else -> default (SPA-style 200 or 404)."""
    def handler(request: httpx.Request):
        url = str(request.url)
        if url in routes:
            return routes[url]
        return default() if default else httpx.Response(404, text="not found")
    return httpx.Client(transport=httpx.MockTransport(handler))


def ok_tls(*_a, **_k):
    return 80


def closed(*_a):
    return False


def good_site_routes():
    return {
        "http://app.example/": httpx.Response(301, headers={"location": "https://app.example/"}),
        "https://app.example": httpx.Response(200, headers={"strict-transport-security": "max-age=31536000"}, content=SPA),
    }


def test_clean_spa_site_has_no_false_alarms():
    # The SPA answers 200 with its HTML for EVERY path, including /.env and /.git/config.
    client = site(good_site_routes(), default=lambda: httpx.Response(200, content=SPA))
    cfg = ProbeConfig(targets=["https://app.example"])
    assert run_probe(cfg, client, is_open=closed, days_left=ok_tls) == []


def test_real_problems_are_found():
    routes = good_site_routes()
    routes["http://app.example/"] = httpx.Response(200, content=SPA)               # no redirect
    routes["https://app.example"] = httpx.Response(200, content=SPA)               # no HSTS
    routes["https://app.example/.env"] = httpx.Response(200, content=b"DB_PASSWORD=hunter2\nAPI_KEY=x\n")
    routes["https://app.example/.git/HEAD"] = httpx.Response(200, content=b"ref: refs/heads/main\n")
    routes["https://app.example/api/bookings"] = httpx.Response(200, json=[{"id": 1}])
    routes["https://app.example/api/me"] = httpx.Response(401, json={"error": "login"})
    client = site(routes)
    cfg = ProbeConfig(targets=["app.example"], must_deny=["https://app.example/api/bookings", "https://app.example/api/me"])
    found = run_probe(cfg, client, is_open=lambda h, p, t: p in (6379, 3000), days_left=lambda *a, **k: 5)
    codes = {f.code for f in found}
    assert "probe_port:app.example:6379" in codes and "probe_port:app.example:3000" in codes
    assert "probe_secret_file:https://app.example/.env" in codes
    assert "probe_secret_file:https://app.example/.git/HEAD" in codes
    assert "probe_api_open:https://app.example/api/bookings" in codes
    assert not any("api/me" in c for c in codes)
    assert {"probe_no_https_redirect:app.example", "probe_no_hsts:app.example", "probe_tls_expiring:app.example"} <= codes
    assert found[0].severity == "critical"  # sorted worst first
    report = format_report(found, ["app.example"])
    assert "hunter2" not in report  # bodies are never printed
    assert should_fail(found, "high") and not should_fail(found, "never")


def test_allowed_ports_are_not_reported():
    cfg = ProbeConfig(targets=["https://app.example"], allowed_ports={22, 80, 443, 8080})
    found = run_probe(cfg, site(good_site_routes()), is_open=lambda h, p, t: p == 8080, days_left=ok_tls)
    assert found == []


def test_invalid_certificate():
    def bad(*_a, **_k):
        err = ssl.SSLCertVerificationError("certificate verify failed")
        err.verify_message = "certificate has expired"
        raise err
    found = run_probe(ProbeConfig(targets=["https://app.example"]), site(good_site_routes()), is_open=closed, days_left=bad)
    assert [f.code for f in found] == ["probe_tls_invalid:app.example"] and "expired" in found[0].detail


def test_parse_list_and_russian_report():
    assert parse_list("https://a.example, b.example\n# comment\n") == ["https://a.example", "b.example"]
    i18n.set_language("ru")
    assert "Наружу ничего не торчит" in format_report([], ["a.example"])
    i18n.set_language("en")
    assert "Nothing exposed" in format_report([], ["a.example"])


def test_cli_requires_targets(monkeypatch, capsys):
    monkeypatch.delenv("SECWATCH_PROBE_TARGETS", raising=False)
    assert main(["probe"]) == 2
    assert "Nothing to check" in capsys.readouterr().err


def test_telegram_errors_are_explained_without_the_token():
    from secwatch.probe import send_telegram
    calls = []

    def handler(request: httpx.Request):
        calls.append(str(request.url))
        if "/botGOOD/" in str(request.url):
            body = request.read().decode()
            return httpx.Response(400, json={"ok": False, "description": "Bad Request: chat not found"}) \
                if '"chat_id":"0"' in body.replace(" ", "") else httpx.Response(200, json={"ok": True})
        return httpx.Response(401, json={"ok": False, "description": "Unauthorized"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert send_telegram(" GOOD\n", "42", "hi", client) is None          # stray whitespace is trimmed
    bad = send_telegram("BAD", "42", "hi", client)
    assert "token is wrong" in bad and "BAD" not in bad
    assert "press Start" in send_telegram("GOOD", "0", "hi", client)
