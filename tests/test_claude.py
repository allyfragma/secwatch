import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from secwatch import claude, db
from secwatch.geo import Geo
from secwatch.summary import build_summary
from secwatch.web import create_app
from secwatch.worker import run_once
from tests.test_pipeline import Recorder

AUTH = ("admin", "test-password")


class FakeMessages:
    def __init__(self, stop_reason="end_turn", text="## Verdict\nNormal background noise."):
        self.calls = []
        self.stop_reason, self.text = stop_reason, text

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(stop_reason=self.stop_reason, model=kwargs["model"],
                               content=[SimpleNamespace(type="thinking", thinking=""),
                                        SimpleNamespace(type="text", text=self.text)])


def fake_client(messages):
    return SimpleNamespace(beta=SimpleNamespace(messages=messages))


def prepared(settings, host):
    settings.allowlist = "198.51.100.7 laptop"   # an own IP that logs in in the sample data
    settings.supabase_project_ref = "secretprojectref"
    run_once(settings, Recorder(settings), Geo("", ""), False)
    return build_summary(settings, geo=Geo("", ""))


def test_brief_has_no_own_identifiers(settings, host):
    s = prepared(settings, host)
    text = claude.copy_prompt(s, "en")
    assert "Answer in English." in text and "secwatch data for" in text
    assert "198.51.100.7" not in text            # own (allowlisted) login IP
    assert "secretprojectref" not in text and "test-password" not in text
    brief = claude.build_brief(s)
    assert brief["ssh_logins"] and all("ip" not in l for l in brief["ssh_logins"])
    assert any(l["own_ip"] for l in brief["ssh_logins"])
    assert brief["top_attacker_ips"] and brief["recommendations"]
    assert "Answer in Russian." in claude.copy_prompt(s, "ru")


def test_api_mode_calls_claude_once_and_caches(settings, host):
    s = prepared(settings, host)
    settings.anthropic_api_key = "sk-ant-test"
    msgs = FakeMessages()
    first = claude.analyze(settings, s, client=fake_client(msgs))
    assert first["text"].startswith("## Verdict") and not first["cached"]
    call = msgs.calls[0]
    assert call["model"] == "claude-opus-5-5" and call["output_config"] == {"effort": "medium"}
    assert call["fallbacks"] == "default" and call["betas"] == ["server-side-fallback-2026-07-01"]
    assert "thinking" not in call and "temperature" not in call
    again = claude.analyze(settings, s, client=fake_client(msgs))
    assert again["cached"] and len(msgs.calls) == 1        # same data -> no second paid call
    claude.analyze(settings, s, force=True, client=fake_client(msgs))
    assert len(msgs.calls) == 2


def test_refusal_is_an_error_not_an_empty_answer(settings, host):
    s = prepared(settings, host)
    settings.anthropic_api_key = "sk-ant-test"
    try:
        claude.analyze(settings, s, client=fake_client(FakeMessages(stop_reason="refusal")))
    except claude.AnalyzeError as exc:
        assert str(exc) == "refusal"
        return
    raise AssertionError("refusal must raise")


def test_web_endpoint_modes_and_csrf_guard(settings, host, monkeypatch):
    prepared(settings, host)
    web = TestClient(create_app(settings))
    assert web.post("/api/analyze", auth=AUTH).status_code == 403                 # no X-Secwatch header
    assert web.post("/api/analyze", headers={"X-Secwatch": "1"}).status_code == 401  # no password
    r = web.post("/api/analyze", auth=AUTH, headers={"X-Secwatch": "1"})
    assert r.status_code == 200 and r.json()["mode"] == "prompt" and "secwatch data for" in r.json()["prompt"]
    page = web.get("/", auth=AUTH).text
    assert 'id="claude-run"' in page and "/static/app.js" in page and 'data-mode="prompt"' in page
    js = web.get("/static/app.js")
    assert js.status_code == 200 and "X-Secwatch" in js.text and "textContent" in js.text

    settings.anthropic_api_key = "sk-ant-test"
    monkeypatch.setattr(claude, "analyze", lambda st, s, force=False: {
        "text": "ok", "model": "claude-opus-5-5", "cached": False, "created": "now"})
    r = web.post("/api/analyze", auth=AUTH, headers={"X-Secwatch": "1"})
    assert r.json() == {"mode": "api", "text": "ok", "model": "claude-opus-5-5", "cached": False, "created": "now"}

    def boom(*a, **k):
        raise claude.AnalyzeError("auth")
    monkeypatch.setattr(claude, "analyze", boom)
    r = web.post("/api/analyze", auth=AUTH, headers={"X-Secwatch": "1"})
    assert r.status_code == 502 and "SECWATCH_ANTHROPIC_API_KEY" in r.json()["error"] and r.json()["prompt"]
