"""'Analyze with Claude': a plain-language review of the day's security summary.

Two modes:
- no API key: a ready prompt (instructions + the day's data) to paste into
  Claude Code, claude.ai or another assistant; nothing is sent anywhere;
- SECWATCH_ANTHROPIC_API_KEY set: the dashboard asks Claude directly and shows
  the answer; one answer per day and data set is cached so re-opening the
  page does not cost money.

Only an aggregated brief is shared: counters, attacker IPs, recommendations,
system events and masked log templates. Allowlisted (own) IPs, login IPs,
host names, tokens and Supabase identifiers are never included.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from . import db
from .config import Settings
from .i18n import get_language

DEFAULT_MODEL = "claude-opus-5-5"
MAX_ITEMS = 15

SYSTEM_PROMPT = """You are a calm, practical security engineer reviewing one day of data from secwatch, \
a monitor on a small self-hosted Linux server (often run by a solo developer, not a security specialist).

Write for that person:
- Start with a one-paragraph verdict: is anything actually dangerous today, or is it the normal \
background noise every public server gets?
- Then list what to do, most important first. For each item: what it is, why it matters for THIS \
server, and the exact command or setting to fix it. Skip items that need no action.
- Point out anything that looks connected (the same IP in several places, a login after brute force, \
a user change, a secret file served) - that is where real incidents show.
- Say plainly when the data is not enough to conclude something, and what to check by hand.
- Do not invent facts that are not in the data. Do not recommend paid products.
- Keep it short: at most about 400 words. Use simple Markdown (headings, lists, code for commands)."""

LANG_NAMES = {"en": "English", "ru": "Russian"}


def _strip(items, keys, limit=MAX_ITEMS):
    return [{k: it.get(k) for k in keys if it.get(k) not in (None, "", [])} for it in (items or [])[:limit]]


def build_brief(s: dict) -> dict:
    """The data shared with Claude: aggregated and without the owner's own identifiers."""
    return {
        "day": s["day"], "timezone": s["timezone"],
        "risk": {"score": s["risk"]["score"], "level": s["risk"]["level"]},
        "totals": {"attack_events": s["attacks"], "attacker_ips": s["attacker_ips"],
                   "ssh_login_attempts": s["ssh_attack_conns"], "fail2ban_bans": s["bans"],
                   "web_attacks": s["web_attacks"], "web_requests": s["web_requests"]},
        "event_kinds": {k["kind"]: k["count"] for k in s.get("kind_rows", [])},
        "top_attacker_ips": _strip(s["top_ips"], ("ip", "count", "country", "asn", "kinds", "banned"), 10),
        "guessed_usernames": _strip(s["usernames"], ("username", "n"), 10),
        "web_targets": _strip(s["web_targets"], ("target", "n", "ips", "labels", "status"), 10),
        # Own logins: no IPs, only the flags that matter.
        "ssh_logins": [{"time": l["time"], "user": l["user"], "method": l["method"], "country": l["country"],
                        "new_ip": l["first_time"], "after_brute_force": l["had_failures"],
                        "own_ip": l["known"] is not None} for l in s["ssh_logins"][:MAX_ITEMS]],
        "secret_files_served": _strip(s["sensitive"], ("time", "target", "status", "ip")),
        "recommendations": _strip(s["recommendations"], ("severity", "title", "detail")),
        "system_events": _strip(s.get("system_events"), ("time", "kind", "target", "detail", "severity")),
        "new_kinds_of_log_events": _strip(s.get("new_log_events"), ("program", "template", "count"), 20),
        "allowlist_entries": s.get("allowlist_size", 0),
    }


def _language_line(lang: str) -> str:
    return f"Answer in {LANG_NAMES.get(lang, 'English')}."


def user_message(brief: dict, lang: str) -> str:
    return (f"{_language_line(lang)}\n\nsecwatch data for {brief['day']} ({brief['timezone']}):\n\n"
            + json.dumps(brief, ensure_ascii=False, indent=1))


def copy_prompt(s: dict, lang: str | None = None) -> str:
    """Everything in one block for pasting into any assistant."""
    lang = lang or get_language()
    return SYSTEM_PROMPT + "\n\n" + user_message(build_brief(s), lang)


class AnalyzeError(Exception):
    pass


def _cache_key(brief: dict, model: str, lang: str) -> str:
    digest = hashlib.sha1(json.dumps([brief, model, lang], sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return f"claude:{brief['day']}:{digest}"


def analyze(settings: Settings, s: dict, force: bool = False, client=None) -> dict:
    """Ask Claude about the day. Returns {text, model, cached, created}."""
    lang = get_language()
    brief = build_brief(s)
    model = settings.claude_model or DEFAULT_MODEL
    key = _cache_key(brief, model, lang)
    with db.connect(settings.db_path) as conn:
        cached = db.get_meta(conn, key)
    if cached and not force:
        return {**json.loads(cached), "cached": True}

    import anthropic  # optional at import time: copy mode works without the SDK

    client = client or anthropic.Anthropic(api_key=settings.anthropic_api_key, timeout=120.0, max_retries=2)
    try:
        response = client.beta.messages.create(
            model=model,
            max_tokens=8000,
            system=SYSTEM_PROMPT,
            output_config={"effort": "medium"},
            # If a safety classifier declines, the API retries on a fallback model in the same call.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            messages=[{"role": "user", "content": user_message(brief, lang)}],
        )
    except anthropic.AuthenticationError:
        raise AnalyzeError("auth") from None
    except anthropic.PermissionDeniedError:
        raise AnalyzeError("permission") from None
    except anthropic.RateLimitError:
        raise AnalyzeError("rate_limit") from None
    except anthropic.APIStatusError as exc:
        raise AnalyzeError(f"api:{exc.status_code}") from None
    except anthropic.APIConnectionError:
        raise AnalyzeError("network") from None

    if response.stop_reason == "refusal":
        raise AnalyzeError("refusal")
    text = "\n".join(b.text for b in response.content if b.type == "text").strip()
    if not text:
        raise AnalyzeError("empty")
    result = {"text": text, "model": response.model,
              "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    with db.connect(settings.db_path) as conn:
        db.set_meta(conn, key, json.dumps(result, ensure_ascii=False))
    return {**result, "cached": False}


def forget_old(conn: sqlite3.Connection, keep_days: int = 14) -> None:
    conn.execute("delete from meta where k like 'claude:%' and substr(k, 8, 10) < date('now', ?)",
                 (f"-{keep_days} days",))
