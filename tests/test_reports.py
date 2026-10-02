"""Reports and the end-to-end promise: `Hunter.demo()` must produce a report
you could actually send to someone.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from polyglot_bug_hunter import Hunter
from polyglot_bug_hunter.hunter import available_capabilities, known_targets
from polyglot_bug_hunter.models import Severity
from polyglot_bug_hunter.report import render
from polyglot_bug_hunter.storage.db import Store


class TestMarkdown:
    def test_contains_the_essentials(self, report):
        md = render.to_markdown(report)
        for needle in ("PolyglotBugHunter-X", report.target, "risk",
                       "only tests systems you own", "| Critical (", "Evidence",
                       "**Fix**", "MIT"):
            assert needle in md, f"markdown missing {needle!r}"

    def test_pluralisation_is_correct(self, report):
        """'1 findings' in a report is the first thing a reader notices."""
        from polyglot_bug_hunter.report.render import plural
        assert plural(1, "finding") == "1 finding"
        assert plural(2, "finding") == "2 findings"
        assert plural(0, "finding") == "0 findings"
        assert plural(3, "entry", "entries") == "3 entries"
        md = render.to_markdown(report)
        assert "1 findings" not in md

    def test_one_section_per_finding(self, report):
        md = render.to_markdown(report)
        assert len(re.findall(r"^### ", md, re.M)) == len(report.findings)

    def test_finding_order_matches_sorted_findings(self, report):
        md = render.to_markdown(report)
        titles = [f.title for f in report.sorted_findings()]
        positions = [md.find(t) for t in titles]
        assert all(p >= 0 for p in positions), "every finding title must appear"
        assert positions == sorted(positions), "markdown must follow severity order"

    def test_payloads_are_shown(self, report):
        md = render.to_markdown(report)
        with_payload = [f for f in report.findings if f.payload]
        if with_payload:
            assert "**Payload used**" in md

    def test_clean_report_says_so_without_pretending(self):
        from polyglot_bug_hunter.models import ScanReport
        md = render.to_markdown(ScanReport(target="https://x"))
        assert "✅" in md
        assert "not proof of safety" in md


class TestHtml:
    def test_is_one_file(self, report, tmp_path):
        path = tmp_path / "r.html"
        path.write_text(render.to_html(report), encoding="utf-8")
        html = path.read_text(encoding="utf-8")
        assert html.startswith("<!doctype html>")
        assert html.rstrip().endswith("</html>")
        assert not re.search(r'<(link|script)\s', html), "no external assets allowed"

    def test_escapes_finding_text(self, report):
        """A finding title containing markup must not become markup."""
        from polyglot_bug_hunter.models import Cvss, Finding, Modality
        rep = type(report)(
            target="https://x",
            findings=[Finding(title="<script>alert(1)</script>", severity=Severity.HIGH,
                              modality=Modality.TEXT, cvss=Cvss.build())],
        )
        html = render.to_html(rep)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_risk_score_is_prominent(self, report):
        assert f">{report.risk_score}<" in render.to_html(report)


class TestSarif:
    def test_shape(self, report):
        sarif = render.to_sarif(report)
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "PolyglotBugHunter-X"
        assert len(run["results"]) == len(report.findings)
        assert run["tool"]["driver"]["rules"]

    def test_every_result_maps_to_a_rule(self, report):
        sarif = render.to_sarif(report)
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        for result in sarif["runs"][0]["results"]:
            assert result["ruleId"] in rule_ids

    def test_severity_maps_to_level(self, report):
        sarif = render.to_sarif(report)
        levels = {r["level"] for r in sarif["runs"][0]["results"]}
        assert levels <= {"error", "warning", "note"}

    def test_fingerprints_are_stable(self, report):
        a = [r["partialFingerprints"]["pbhxFingerprint"]
             for r in render.to_sarif(report)["runs"][0]["results"]]
        b = [r["partialFingerprints"]["pbhxFingerprint"]
             for r in render.to_sarif(report)["runs"][0]["results"]]
        assert a == b


class TestSave:
    def test_writes_all_four_formats(self, report, tmp_path):
        paths = render.save(report, tmp_path)
        assert set(paths) == {"markdown", "html", "json", "sarif"}
        for kind, path in paths.items():
            assert Path(path).is_file(), kind
            assert Path(path).stat().st_size > 200, kind

    def test_json_round_trips(self, report, tmp_path):
        data = json.loads(Path(render.save(report, tmp_path)["json"]).read_text())
        assert data["target"] == report.target
        assert len(data["findings"]) == len(report.findings)

    def test_basename_may_include_a_directory(self, report, tmp_path):
        paths = render.save(report, tmp_path, basename="run-42/latest")
        assert "run-42" in paths["markdown"]
        assert Path(paths["markdown"]).is_file()

    def test_saving_an_unscanned_hunter_raises(self, tmp_path):
        """Silently writing an empty report is how someone emails a manager
        '0 findings' about a scan that never ran."""
        with pytest.raises(ValueError, match="nothing to save"):
            Hunter().save(tmp_path)


class TestStore:
    def test_saves_and_reads_history(self, report, tmp_path):
        store = Store(tmp_path / "h.duckdb")
        store.save(report)
        history = store.history()
        assert len(history) == 1
        assert history[0]["target"] == report.target
        assert history[0]["findings"] == len(report.findings)
        store.close()

    def test_backend_is_reported(self, tmp_path):
        store = Store(tmp_path / "b.duckdb")
        info = store.info()
        assert info.backend in ("duckdb", "sqlite3")
        assert Path(info.path).exists()
        store.close()

    def test_modality_breakdown(self, report, tmp_path):
        store = Store(tmp_path / "m.duckdb")
        store.save(report)
        breakdown = store.modality_breakdown()
        assert breakdown
        assert {row["modality"] for row in breakdown} == set(report.by_modality())
        store.close()

    def test_top_findings(self, report, tmp_path):
        store = Store(tmp_path / "t.duckdb")
        store.save(report)
        top = store.top_findings(3)
        assert len(top) <= 3
        assert top == sorted(top, key=lambda r: -r["cvss"])
        store.close()

    def test_two_scans_accumulate(self, tmp_path):
        store = Store(tmp_path / "a.duckdb")
        store.save(Hunter.demo())
        store.save(Hunter.demo())
        assert store.info().scans == 2
        store.close()


class TestEndToEnd:
    def test_demo_finds_the_planted_bugs(self, report):
        """Every flaw we deliberately planted must be reported. This is the
        recall assertion that matters."""
        titles = " | ".join(f.title.lower() for f in report.findings)
        expected = {
            "sql injection": "sqli",
            "idor": "idor",
            "template injection": "ssti",
            "open redirect": "redirect",
            "httponly": "cookie flags",
            "content-security-policy": "headers",
            ".env": "exposure",
            "credential in html comment": "secret",
            "prompt-injection": "ai injection",
            "csrf": "csrf",
            "samesite": "cookie flags",
        }
        for needle, why in expected.items():
            assert needle in titles, f"missed {why} ({needle!r})"

    def test_demo_is_fast_enough_for_a_space(self, report):
        assert report.duration < 60, "a Space visitor waits less than a minute, ideally 5s"

    def test_every_finding_is_complete(self, report):
        for f in report.findings:
            assert f.title and f.severity and f.modality
            assert f.description, f"{f.title} has no description"
            assert f.remediation, f"{f.title} has no remediation"
            assert f.evidence.proof or f.evidence.response_snippet, \
                f"{f.title} has no evidence"
            assert f.tags, f"{f.title} has no tags"

    def test_severities_are_sane(self, report):
        for f in report.findings:
            assert f.severity in Severity
            assert 0.0 <= f.cvss.score <= 10.0
        assert report.worst in Severity

    def test_risk_score_is_high_for_the_deliberately_broken_target(self, report):
        assert report.risk_score > 50

    def test_no_false_criticals_are_impossible_because_there_are_no_clean_pages(self, report):
        assert len(report.assets) >= 5, "the crawl should have found the demo's endpoints"

    def test_notes_record_the_policy(self, report):
        joined = " ".join(report.notes)
        assert "Requests sent" in joined
        assert "Rate limit" in joined

    def test_demo_note_discloses_it_is_local(self, report):
        assert "Demo mode" in report.notes[0]

    def test_capabilities_reflect_the_install(self):
        caps = available_capabilities()
        assert set(caps) == {"playwright", "duckdb", "pillow", "tesseract",
                             "whisper", "requests"}
        assert all(isinstance(v, bool) for v in caps.values())

    def test_known_targets_are_documented_safe_ones(self):
        urls = " ".join(u for _, u, _ in known_targets())
        assert "httpbin.org" in urls and "testfire" in urls
        assert "127.0.0.1" not in urls.replace("http://127.0.0.1/", ""), \
            "the localhost demo is exposed through the classmethod, not the target list"


class TestPayloadRouting:
    def test_param_name_routes_to_the_right_class(self):
        from polyglot_bug_hunter import payloads
        assert any(p.vuln == "traversal" for p in payloads.for_param("file"))
        assert any(p.vuln == "ssrf" for p in payloads.for_param("url"))
        assert any(p.vuln == "prompt-injection" for p in payloads.for_param("message"))
        assert any(p.vuln == "sqli" for p in payloads.for_param("id"))
        assert any(p.vuln == "cmdi" for p in payloads.for_param("cmd"))

    def test_unknown_param_still_gets_usable_coverage(self):
        from polyglot_bug_hunter import payloads
        got = payloads.for_param("zzzz", 6)
        assert got and len(got) == 6
        assert any(p.vuln == "xss" for p in got), "reflection check is universal"

    def test_budget_is_respected(self):
        from polyglot_bug_hunter import payloads
        for budget in (1, 3, 6, 10):
            assert len(payloads.for_param("q", budget)) <= budget

    def test_no_duplicate_payloads_in_a_set(self):
        from polyglot_bug_hunter import payloads
        for name in ("id", "file", "url", "message", "q"):
            values = [p.value for p in payloads.for_param(name, 12)]
            assert len(values) == len(set(values)), name

    def test_stats_are_consistent(self):
        from polyglot_bug_hunter import payloads
        stats = payloads.stats()
        assert stats["total"] == len(payloads.ALL_PAYLOADS)
        assert stats["polyglot"] == sum(1 for p in payloads.ALL_PAYLOADS if p.polyglot)
        assert sum(stats["per_class"].values()) == stats["total"]


class TestDeduplication:
    def test_host_scope_findings_collapse(self, report):
        env = [f for f in report.findings if ".env" in f.title]
        assert len(env) == 1, "one row for the whole host, not one per page"
        assert env[0].affected_pages, "the collapsed row must count its pages"

    def test_endpoint_scope_findings_stay_per_path(self, report):
        sqli = [f for f in report.findings if f.title.startswith("SQL injection")]
        endpoints = {f.endpoint for f in sqli}
        assert len(endpoints) >= 1
        assert all(f.affected_pages == [] for f in sqli if f.scope == "endpoint")


class TestDemoTarget:
    """The demo target is a fixture. If it stops being broken the recall test
    above becomes meaningless, so assert its planted bugs directly."""

    @pytest.mark.parametrize("path,expect", [
        ("/", "PBHX-DEMO"),
        ("/search?q=PBHX7", "PBHX7"),
        ("/.env", "SECRET_KEY"),
        ("/robots.txt", "Disallow"),
    ])
    def test_endpoints_respond(self, http, demo_server, path, expect):
        r = http.get(demo_server.url.rstrip("/") + path)
        assert r.ok and expect in r.body

    def test_search_reflects_raw(self, http, demo_server):
        r = http.get(demo_server.url.rstrip("/") + "/search", params={"q": "<b>x</b>"})
        assert "<b>x</b>" in r.body, "unescaped reflection is the planted XSS"

    def test_customer_page_escapes(self, http, demo_server):
        r = http.get(demo_server.url.rstrip("/") + "/customer", params={"id": "1"})
        assert "alice@example.invalid" in r.body

    @pytest.mark.parametrize("pid,expect", [
        ("1", "rows"), ("' OR 1=1 -- ", "all"), ("'PBHX7", "error"),
        ("1' ORDER BY 99 -- -", "error"),
    ])
    def test_sql_simulation(self, pid, expect):
        from polyglot_bug_hunter.demo_target import _simulate_query
        assert _simulate_query(pid)[0] == expect

    def test_comment_stores_reflects(self, http, demo_server):
        r = http.post(demo_server.url.rstrip("/") + "/comment",
                      data={"user": "u", "body": "<script>x</script>"})
        assert "<script>x</script>" in r.body, "stored XSS is the planted bug"

    def test_redirect_goes_anywhere(self, http, demo_server):
        r = http.get(demo_server.url.rstrip("/") + "/redirect",
                     params={"next": "https://evil.example/"})
        assert r.status == 302
        assert r.header("location") == "https://evil.example/"

    def test_template_evaluates(self, http, demo_server):
        r = http.get(demo_server.url.rstrip("/") + "/render", params={"tpl": "{{7*7}}"})
        assert "49" in r.body

    def test_binds_to_loopback_only(self, demo_server):
        assert demo_server.url.startswith("http://127.0.0.1:")

    def test_banner_discloses_intent(self, http, demo_server):
        body = http.get(demo_server.url).body
        assert "intentionally vulnerable" in body
        assert "Do not deploy" in body
