"""User-facing text: English by default, Russian with SECWATCH_LANG=ru.

Catalogs are flat JSON files in secwatch/locales/. Lookup order: the current
language, then English, then the key itself.
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources

DEFAULT = "en"
LANGUAGES = ("en", "ru")

_lang = DEFAULT


@cache
def catalog(lang: str) -> dict[str, str]:
    text = resources.files(__package__).joinpath("locales", f"{lang}.json").read_text(encoding="utf-8")
    return json.loads(text)


def normalize(lang: str | None) -> str:
    code = (lang or "").strip().lower().replace("-", "_").split("_")[0]
    return code if code in LANGUAGES else DEFAULT


def set_language(lang: str | None) -> str:
    global _lang
    _lang = normalize(lang)
    return _lang


def get_language() -> str:
    return _lang


def translate(lang: str, key: str, **params) -> str:
    for code in (normalize(lang), DEFAULT):
        text = catalog(code).get(key)
        if text is not None:
            break
    else:
        return key
    try:
        return text.format(**params)
    except (KeyError, IndexError, ValueError):
        return text


def t(key: str, **params) -> str:
    return translate(_lang, key, **params)


def has(key: str) -> bool:
    return key in catalog(_lang) or key in catalog(DEFAULT)


def plural_form(n: int, lang: str | None = None) -> str:
    """'one', 'few' or 'many'. English uses only 'one' and 'many'."""
    n = abs(n)
    if normalize(lang or _lang) == "ru":
        if n % 10 == 1 and n % 100 != 11:
            return "one"
        if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
            return "few"
        return "many"
    return "one" if n == 1 else "many"


def plural(n: int, key: str) -> str:
    """The word for n items: plural(5, "plural.object") -> "objects" / "объектов"."""
    return t(f"{key}.{plural_form(n)}")
