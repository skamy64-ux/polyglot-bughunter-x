"""i18n. 12 languages, one key set, zero drama.

en.json is the master. Every other file is a translation of it. Missing keys
fall back to English, then to the key itself, so a half-finished translation
degrades to English instead of showing raw snake_case to a Korean user.
"""

from __future__ import annotations

import json
import os
import re
from functools import cache
from pathlib import Path
from typing import Any

SUPPORTED = ["en", "zh", "ja", "ko", "id", "es", "ar", "ru", "de", "fr", "pt", "hi"]

# display name in its OWN language. don't translate these, that's rude.
NATIVE_NAMES = {
    "en": "English",
    "zh": "中文",
    "ja": "日本語",
    "ko": "한국어",
    "id": "Bahasa Indonesia",
    "es": "Español",
    "ar": "العربية",
    "ru": "Русский",
    "de": "Deutsch",
    "fr": "Français",
    "pt": "Português",
    "hi": "हिन्दी",
}

FLAGS = {
    "en": "🇬🇧", "zh": "🇨🇳", "ja": "🇯🇵", "ko": "🇰🇷", "id": "🇮🇩", "es": "🇪🇸",
    "ar": "🇸🇦", "ru": "🇷🇺", "de": "🇩🇪", "fr": "🇫🇷", "pt": "🇵🇹", "hi": "🇮🇳",
}

RTL = {"ar"}

# extra fallbacks for the same language across writing systems
_ALIASES = {
    "zh-cn": "zh", "zh-tw": "zh", "zh-hans": "zh", "zh-hant": "zh",
    "pt-br": "pt", "en-us": "en", "en-gb": "en",
    "in": "id",  # the classic "in" -> "id" browser bug, still around in 2026
    "iw": "he",
}


def locale_dir() -> Path:
    """Find locales/ whether we're installed as a package or running from repo."""
    env = os.getenv("PBHX_LOCALES")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "locales"
        if cand.is_dir():
            return cand
    return here.parent / "locales"


@cache
def load(code: str) -> dict[str, Any]:
    code = normalize(code)
    path = locale_dir() / f"{code}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def normalize(tag: str | None) -> str:
    """'zh-Hant-TW' -> 'zh'. 'auto'/'navigator.language'/None -> 'en'."""
    if not tag:
        return "en"
    tag = str(tag).strip().replace("_", "-").lower()
    if tag in ("auto", "browser", "default"):
        return detect()
    tag = _ALIASES.get(tag, tag)
    base = tag.split("-")[0]
    base = _ALIASES.get(base, base)
    if base in SUPPORTED:
        return base
    # try the 2-letter lang, then give up and speak english
    return base[:2] if base[:2] in SUPPORTED else "en"


def detect(navigator_language: str | None = None, *extra: str | None) -> str:
    """Auto-detect. Order: browser -> HF space locale -> env -> english."""
    for candidate in (navigator_language, *extra, os.getenv("PBHX_LANG"),
                      os.getenv("GRADIO_LANGUAGE"), os.getenv("LANG"), os.getenv("LC_ALL")):
        if candidate:
            tag = normalize(str(candidate))
            if tag != "en" or str(candidate).lower().startswith("en"):
                return tag
    return "en"


class Translator:
    """t() is the whole API. Flattened keys keep JSON readable."""

    def __init__(self, code: str = "auto") -> None:
        self.code = normalize(code)
        self.base = load(self.code)
        self.en = load("en")

    # -- lookup ------------------------------------------------------------

    def get(self, key: str, **fmt: Any) -> str:
        val = self.base.get(key)
        if val is None:
            val = self.en.get(key)
        if val is None:
            # last resort: title-case the key so it reads as words not code
            return key.replace("_", " ").replace(".", " ").strip().title()
        if fmt:
            try:
                val = val.format(**fmt)
            except (KeyError, IndexError, ValueError):
                pass
        return str(val)

    __call__ = get

    def is_rtl(self) -> bool:
        return self.code in RTL

    def flag(self) -> str:
        return FLAGS.get(self.code, "🌐")

    def label(self) -> str:
        return f"{FLAGS.get(self.code, '🌐')} {NATIVE_NAMES.get(self.code, self.code)}"

    def options(self) -> list[tuple[str, str]]:
        """For gradio.Dropdown. Label is native, value is the code."""
        return [(f"{FLAGS[c]} {NATIVE_NAMES[c]}", c) for c in SUPPORTED]

    # -- interpolation helpers used by report renderers ---------------------

    def severity(self, key: str) -> str:
        return self.get(f"severity.{key}")

    def status(self, key: str) -> str:
        return self.get(f"status.{key}")


def html_attrs(code: str) -> str:
    """<html lang=.. dir=..> bits for the HTML report."""
    code = normalize(code)
    return f'lang="{code}" dir="{"rtl" if code in RTL else "ltr"}"'


_SCRIPT_RE = re.compile(r"^[A-Za-z]+[-_]")


def dir_for(script: str | None) -> str:
    if not script:
        return "ltr"
    tag = _SCRIPT_RE.sub("", str(script))
    return "rtl" if tag.lower().startswith("ar") else "ltr"
