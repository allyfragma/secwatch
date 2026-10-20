import re
import string

import pytest
from fastapi.testclient import TestClient

from secwatch import i18n
from secwatch.alerts import format_digest
from secwatch.config import Settings
from secwatch.geo import Geo
from secwatch.summary import build_summary
from secwatch.web import create_app
from secwatch.worker import run_once

CYRILLIC = re.compile("[А-Яа-яЁё]")


class Silent:
    def send(self, text: str, category: str = "digest") -> bool:
        return True


def placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name is not None}


def test_catalogs_have_same_keys_and_placeholders():
    en, ru = i18n.catalog("en"), i18n.catalog("ru")
    assert set(en) == set(ru)
    for key in en:
        assert placeholders(en[key]) == placeholders(ru[key]), key
        assert all(name.isidentifier() for name in placeholders(en[key])), key
        params = dict.fromkeys(placeholders(en[key]), "x")
        en[key].format(**params), ru[key].format(**params)  # no stray braces


def test_english_catalog_has_no_cyrillic():
    assert not [k for k, v in i18n.catalog("en").items() if CYRILLIC.search(v)]


def test_english_dashboard_and_digest(settings):
    i18n.set_language("en")
    geo = Geo("", "")
    run_once(settings, Silent(), geo, False)
    s = build_summary(settings, geo=geo)
    digest = format_digest(s)
    assert "What to fix" in digest and not CYRILLIC.search(digest)
    r = TestClient(create_app(settings)).get("/", auth=("admin", "test-password"))
    assert r.status_code == 200 and '<html lang="en">' in r.text
    assert "What to fix" in r.text and "203.0.113.66" in r.text
    assert not CYRILLIC.findall(r.text)


def test_russian_dashboard_lang_attribute(settings):
    r = TestClient(create_app(settings)).get("/", auth=("admin", "test-password"))
    assert '<html lang="ru">' in r.text and "Что исправить" in r.text


def test_api_summary_keeps_keys(settings):
    i18n.set_language("en")
    run_once(settings, Silent(), Geo("", ""), False)
    j = TestClient(create_app(settings)).get("/api/summary", auth=("admin", "test-password")).json()
    assert j["risk"]["level"] == "critical" and j["risk"]["level_ru"] == "критично"
    assert j["risk"]["level_label"] == "critical"
    assert {"severity_ru", "severity_label"} <= set(j["recommendations"][0])


def test_fallback(monkeypatch):
    catalogs = {"en": {"a": "A {n}", "b": "B"}, "ru": {"a": "А {n}"}}
    monkeypatch.setattr(i18n, "catalog", lambda lang: catalogs[lang])
    i18n.set_language("ru")
    assert i18n.t("a", n=1) == "А 1"
    assert i18n.t("b") == "B"  # missing in Russian -> English
    assert i18n.t("nope.key") == "nope.key"  # missing everywhere -> the key
    assert i18n.t("a") == "А {n}"  # missing parameter -> unformatted text, no exception
    i18n.set_language("de")
    assert i18n.get_language() == "en" and i18n.t("a", n=2) == "A 2"


@pytest.mark.parametrize("raw, lang", [("ru", "ru"), ("RU", "ru"), ("ru_RU", "ru"), ("ru-RU", "ru"),
                                       ("en", "en"), ("", "en"), (None, "en"), ("fr", "en")])
def test_set_language_normalizes(raw, lang):
    assert i18n.set_language(raw) == lang == i18n.get_language()


def test_settings_lang(monkeypatch):
    monkeypatch.delenv("SECWATCH_LANG", raising=False)
    assert Settings().lang == "en"
    monkeypatch.setenv("SECWATCH_LANG", "ru")
    assert Settings().lang == "ru"


def test_plural():
    i18n.set_language("ru")
    assert [i18n.plural(n, "plural.object") for n in (0, 1, 2, 4, 5, 11, 12, 14, 21, 101, 111, 1000)] == [
        "объектов", "объект", "объекта", "объекта", "объектов", "объектов", "объектов", "объектов",
        "объект", "объект", "объектов", "объектов"]
    i18n.set_language("en")
    assert [i18n.plural(n, "plural.object") for n in (0, 1, 2, 11, 21)] == [
        "objects", "object", "objects", "objects", "objects"]
    assert i18n.plural_form(3, "ru") == "few" and i18n.plural_form(3, "en") == "many"
