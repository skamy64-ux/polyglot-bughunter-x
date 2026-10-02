"""i18n. Twelve languages, one key set. A missing key must degrade to English,
never to raw snake_case in someone's face."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from polyglot_bug_hunter.i18n import (
    FLAGS,
    NATIVE_NAMES,
    RTL,
    SUPPORTED,
    Translator,
    detect,
    load,
    normalize,
)

LOCALES = Path(__file__).resolve().parents[1] / "locales"


class TestLocaleFiles:
    def test_twelve_files_exist(self):
        assert len(SUPPORTED) == 12
        for code in SUPPORTED:
            assert (LOCALES / f"{code}.json").is_file(), f"missing {code}.json"

    @pytest.mark.parametrize("code", SUPPORTED)
    def test_valid_json_with_meta(self, code):
        data = json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))
        assert data["_meta"]["code"] == code
        assert data["_meta"]["dir"] in ("ltr", "rtl")

    def test_english_is_the_master(self):
        en = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
        assert "master key set" in en["_meta"]["note"].lower()

    @pytest.mark.parametrize("code", SUPPORTED)
    def test_no_key_orphans(self, code):
        """Every locale uses exactly the english key set - no extras, no gaps."""
        en = {k for k in json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
              if not k.startswith("_meta")}
        other = {k for k in json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))
                 if not k.startswith("_meta")}
        assert other - en == set(), f"{code} has keys english does not"
        assert en - other == set(), f"{code} is missing keys: {sorted(en - other)[:5]}"

    @pytest.mark.parametrize("code", SUPPORTED)
    def test_no_blank_values(self, code):
        data = json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))
        for k, v in data.items():
            if k.startswith("_meta"):
                continue
            assert isinstance(v, str) and v.strip(), f"{code}.{k} is blank"

    @pytest.mark.parametrize("code", SUPPORTED)
    def test_placeholders_match_english(self, code):
        """A missing {placeholder} renders as a literal brace in production."""
        import re
        en = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
        other = json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))
        ph = re.compile(r"\{(\w+)\}")
        for k, v in en.items():
            if k.startswith("_meta"):
                continue
            assert set(ph.findall(v)) == set(ph.findall(other[k])), \
                f"{code}.{k} placeholders differ"

    def test_only_arabic_is_rtl(self):
        assert {"ar"} == RTL
        for code in SUPPORTED:
            expected = "rtl" if code == "ar" else "ltr"
            assert Translator(code).is_rtl() == (expected == "rtl")


class TestNormalisation:
    @pytest.mark.parametrize("tag,expected", [
        ("ja", "ja"), ("ja-JP", "ja"), ("JA_jp", "ja"),
        ("zh-CN", "zh"), ("zh-TW", "zh"), ("zh-Hant", "zh"),
        ("pt-BR", "pt"), ("en-GB", "en"),
        ("in", "id"),          # the classic browser bug, still shipping in 2026
        ("ar-EG", "ar"), ("ar_SA", "ar"),
        ("hi", "hi"), ("ru", "ru"), ("ko-KR", "ko"), ("de-AT", "de"),
        ("fr-CA", "fr"), ("id-ID", "id"), ("es-MX", "es"), ("ja-JP", "ja"),
        ("xx-YY", "en"), ("", "en"), (None, "en"), ("klingon", "en"),
    ])
    def test_tags_normalise(self, tag, expected):
        assert normalize(tag) == expected

    @pytest.mark.parametrize("tag,expected", [
        ("ja-JP", "ja"), ("zh-TW", "zh"), ("ar", "ar"), ("pt-BR", "pt"),
        ("in", "id"), ("en-US", "en"), ("de", "de"),
    ])
    def test_auto_detection(self, tag, expected):
        assert detect(tag) == expected


class TestTranslator:
    def test_known_keys_resolve(self):
        en = Translator("en")
        assert en.get("nav.scan") == "Scan"
        assert en.severity("critical") == "Critical"

    def test_translations_differ_from_english(self):
        """If a translation is identical to english, we shipped a copy-paste."""
        en = json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))
        for code in SUPPORTED:
            if code == "en":
                continue
            data = json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))
            differing = sum(1 for k in en if not k.startswith("_meta") and data[k] != en[k])
            assert differing > len(en) * 0.8, f"{code} only translated {differing} keys"

    def test_unknown_key_falls_back_to_english(self):
        t = Translator("ja")
        assert t.get("nav.scan") == load("ja")["nav.scan"]
        assert t.get("does.not.exist") == "Does Not Exist"

    def test_interpolation(self):
        t = Translator("en")
        # extra kwargs the key does not use must not explode
        assert t.get("result.download", nope="x") == "Download report"
        # and a key that does use them must substitute them
        t.base["test.count"] = "{n} findings in {where}"
        assert t.get("test.count", n=7, where="en") == "7 findings in en"

    def test_interpolation_survives_a_bad_format_string(self):
        t = Translator("en")
        t.base["test.broken"] = "{missing}"
        assert t.get("test.broken", wrong="x") == "{missing}", \
            "a missing placeholder must render literally, not raise"

    def test_dropdown_options(self):
        opts = Translator("en").options()
        assert len(opts) == 12
        labels = [label for label, _ in opts]
        values = [value for _, value in opts]
        assert values == SUPPORTED
        assert all(NATIVE_NAMES[c] in lbl for c, lbl in zip(values, labels, strict=True))
        assert all(FLAGS[c] in lbl for c, lbl in zip(values, labels, strict=True))

    def test_native_names_are_in_their_own_script(self):
        """Translating a language's name is how you insult a user."""
        assert NATIVE_NAMES["ja"] == "日本語"
        assert NATIVE_NAMES["ar"] == "العربية"
        assert NATIVE_NAMES["zh"] == "中文"
        assert NATIVE_NAMES["ru"] == "Русский"

    @pytest.mark.parametrize("code", SUPPORTED)
    def test_every_locale_loads_and_answers(self, code):
        t = Translator(code)
        for key in ("nav.scan", "nav.report", "scan.run", "severity.high"):
            value = t.get(key)
            assert value and "_" not in value.split()[0], f"{code}.{key} looks like a raw key"

    def test_state_isolation_between_translators(self):
        a, b = Translator("fr"), Translator("ar")
        assert a.code == "fr" and b.code == "ar"
        assert a.get("nav.scan") != b.get("nav.scan")
        assert a.get("nav.scan") == "Scanner"


class TestReportLocalisation:
    def test_report_renders_in_every_language(self, report):
        from polyglot_bug_hunter.report import render
        for code in SUPPORTED:
            md = render.to_markdown(report, Translator(code))
            assert "PolyglotBugHunter-X" in md
            assert len(md) > 500

    def test_html_direction_follows_the_language(self, report):
        from polyglot_bug_hunter.report import render
        ar = render.to_html(report, Translator("ar"))
        en = render.to_html(report, Translator("en"))
        assert 'dir="rtl"' in ar and 'lang="ar"' in ar
        assert 'dir="ltr"' in en and 'lang="en"' in en

    def test_html_is_self_contained(self, report):
        """No external CSS/JS: the report must open from an email offline."""
        from polyglot_bug_hunter.report import render
        html = render.to_html(report, Translator("en"))
        assert "<style>" in html
        assert "src=\"http" not in html and "href=\"http" not in html

    def test_summary_line_is_localised(self, report):
        from polyglot_bug_hunter.report import render
        assert render.summarize(report, Translator("en"))
        assert render.summarize(report, Translator("zh")) != render.summarize(report, Translator("en"))
