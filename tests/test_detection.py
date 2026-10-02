"""Detection. These assert the *verdicts* on a target whose flaws we control,
which is the only honest way to test a scanner: the ground truth is known.
"""

from __future__ import annotations

import pytest

from polyglot_bug_hunter.scanner import access, passive, race, text
from polyglot_bug_hunter.scanner.text import row_count


def probe(http, url, param, value="", budget=6):
    return text.probe_parameter(http, url, param, value, budget=budget)


def verdicts(injections):
    return {i.payload.label: i.verdict for i in injections}


class TestSqlInjection:
    @pytest.mark.parametrize("payload_label,expected", [
        ("tautology-comment", "vulnerable"),   # row count grows
        ("union-null", "vulnerable"),           # db error leaked
        ("order-by-probe", "vulnerable"),      # 5xx flip
        ("quote-break", "vulnerable"),         # syntax error
    ])
    def test_detects_each_signal(self, http, demo_server, payload_label, expected):
        url = demo_server.url.rstrip("/") + "/product"
        got = verdicts(probe(http, url, "id", "1"))
        assert got.get(payload_label) == expected, f"{got}"

    def test_row_count_growth_is_the_signal(self, http, demo_server):
        """`OR 1=1` must move the row count, not just the status."""
        url = demo_server.url.rstrip("/") + "/product"
        http.get(url + "?id=1")   # warm the baseline so timing is not skewed
        got = verdicts(probe(http, url, "id", "1"))
        assert got["tautology-comment"] == "vulnerable"
        assert "row count" in next(i.signals for i in
                                   probe(http, url, "id", "1")
                                   if i.payload.label == "tautology-comment")[0]

    def test_clean_parameter_is_clean(self, http, demo_server):
        """404 on a nonexistent key is correct behaviour, not a filter bypass."""
        url = demo_server.url.rstrip("/") + "/customer"
        assert all(v == "clean" for v in verdicts(probe(http, url, "id", "1")).values())

    def test_404_is_never_reported_as_injection(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/customer"
        for inj in probe(http, url, "id", "1"):
            assert inj.verdict == "clean", f"{inj.payload.label} -> {inj.verdict} {inj.signals}"

    def test_5xx_is_data_not_an_error(self, http, demo_server):
        """A 500 is the proof; it must not be swallowed as a transport error."""
        url = demo_server.url.rstrip("/") + "/product"
        r = http.get(url + "?id=" + "'")
        assert r.status == 500
        assert r.body, "the 500 body is the evidence and must be captured"
        assert r.content_type, "headers must be captured on error responses too"

    def test_row_count_reads_tables_lists_and_json(self):
        assert row_count(type("R", (), {"body": "<tr><td>1</td></tr><tr><td>2</td></tr>"})()) == 2
        assert row_count(type("R", (), {"body": "<li>a</li><li>b</li><li>c</li>"})()) == 3
        assert row_count(type("R", (), {"body": '[{"id":1},{"id":2}]'})()) == 2
        assert row_count(type("R", (), {"body": "nothing here"})()) == 0


class TestSsti:
    def test_arithmetic_is_proof(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/render"
        got = verdicts(probe(http, url, "tpl", "hi"))
        assert got.get("template-arith") == "vulnerable"

    def test_non_template_page_is_not_vulnerable(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/search"
        got = verdicts(probe(http, url, "q", "widget"))
        assert got.get("template-arith") != "vulnerable"


class TestXss:
    def test_unescaped_reflection(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/search"
        got = verdicts(probe(http, url, "q", "widget"))
        assert got.get("reflected-marker") == "vulnerable"
        assert got.get("attr-breakout-svg") == "vulnerable"

    def test_escaped_output_is_not_xss(self, http, demo_server):
        """The demo html.escape()s the customer fields, so nothing is raw."""
        url = demo_server.url.rstrip("/") + "/customer"
        got = verdicts(probe(http, url, "id", "1"))
        assert set(got.values()) == {"clean"}, got

    def test_finding_carries_the_payload_and_proof(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/search"
        injs = probe(http, url, "q", "widget")
        finding = next(f for i in injs
                       for f in [text.to_finding(i, i.baseline, url)] if f and f.cvss.score > 0)
        assert finding.payload
        assert finding.evidence.proof
        assert finding.remediation
        assert finding.parameter == "q"


class TestSsrfAndRedirect:
    def test_open_redirect_via_location_header(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/redirect"
        got = verdicts(probe(http, url, "next", "/"))
        assert "abs-redirect" in got
        assert any("redirected to our host" in s
                   for i in probe(http, url, "next", "/") for s in i.signals)

    def test_non_redirecting_page_is_clean(self, http, demo_server):
        """A redirect payload against a page that never redirects: nothing fires."""
        url = demo_server.url.rstrip("/") + "/redirect"
        assert verdicts(probe(http, url, "id", "1")).get("abs-redirect") is None


class TestIdor:
    def test_adjacent_id_returns_other_pii(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/customer"
        res = access.analyze(http, url, "id", "1")
        assert res.vulnerable
        assert res.probe_value == "2"
        finding = access.idor_to_finding(res)
        assert finding and finding.severity.value == "critical"
        assert finding.cwe == "CWE-639"

    @pytest.mark.parametrize("value,expected", [
        ("42", ["43", "44"]),
        ("0", ["1", "2"]),
        ("123e4567-e89b-12d3-a456-426614174000",
         ["123e4567-e89b-12d3-a456-426614174001",
          "123e4567-e89b-12d3-a456-426614174002"]),
    ])
    def test_neighbours_stay_in_the_id_space(self, value, expected):
        assert access.neighbours(value, 2) == expected

    def test_non_id_param_not_walked(self):
        assert not access.looks_like_id("q")
        assert not access.looks_like_id("search")
        assert access.looks_like_id("id")
        assert access.looks_like_id("user_id")

    def test_missing_record_is_not_idor(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/customer"
        res = access.analyze(http, url, "id", "9999")   # no such customer
        assert not res.vulnerable


class TestCsrf:
    def test_post_form_without_token_is_high_risk(self):
        form = {"action": "/pay", "method": "POST",
                "fields": [{"name": "amount", "type": "text", "value": "10"}]}
        a = race.assess_csrf(form, "<html></html>")
        assert a.risk == "high"
        finding = race.csrf_to_finding(a, "/pay")
        assert finding and finding.cwe == "CWE-352"

    def test_post_form_with_token_is_low_risk(self):
        html = '<input name="csrf_token" value="abcdef123456">'
        form = {"action": "/pay", "method": "POST",
                "fields": [{"name": "csrf_token", "type": "hidden", "value": "abcdef123456"}]}
        assert race.assess_csrf(form, html).risk == "low"
        assert race.csrf_to_finding(race.assess_csrf(form, html), "/pay") is None

    def test_get_form_is_never_flagged(self):
        form = {"action": "/s", "method": "GET",
                "fields": [{"name": "q", "type": "text", "value": ""}]}
        assert race.assess_csrf(form, "").risk == "low"


class TestRace:
    def test_identical_responses_are_flagged_for_review(self):
        r = race.RaceResult(url="/x", method="POST", threads=6,
                            statuses=[200] * 6, bodies=["ok"] * 6)
        assert r.interesting
        finding = race.race_to_finding(r, None, "/x")
        assert finding and finding.cwe == "CWE-362"
        assert finding.confidence.value == "low", "a race hint must not claim certainty"

    def test_distinct_responses_are_not_flagged(self):
        r = race.RaceResult(url="/x", method="POST", threads=3,
                            statuses=[200, 200, 200],
                            bodies=[f"body-{i}" for i in range(3)])
        assert not r.interesting
        assert race.race_to_finding(r, None, "/x") is None

    def test_failures_are_not_a_race(self):
        r = race.RaceResult(url="/x", method="POST", threads=4,
                            statuses=[0, 0, 0, 0], bodies=["", "", "", ""])
        assert not r.interesting


class TestPassive:
    def test_missing_headers_on_the_demo(self, http, demo_server):
        r = http.get(demo_server.url)
        found = passive.run(http, r.url, r, deep=True)
        titles = " | ".join(f.title for f in found.findings)
        assert "content-security-policy" in titles
        assert "strict-transport-security" not in titles, "http, so HSTS is N/A"
        assert "http://127.0.0.1" in str(found.asset_notes) or found.title

    def test_exposed_env_file_is_critical(self, http, demo_server):
        found = passive.check_exposure(http, demo_server.url, budget=2)
        env = [f for f in found if ".env" in f.title]
        assert env and env[0].severity.value == "critical"

    def test_cookie_flags(self, http, demo_server):
        r = http.post(demo_server.url.rstrip("/") + "/comment",
                      data={"user": "x", "body": "hi"})
        titles = " ".join(f.title for f in passive.check_cookies(r, r.url))
        assert "HttpOnly" in titles and "SameSite" in titles
        # Secure is only wrong over https; the demo is http, so it must not fire
        assert "Secure" not in titles

    def test_secure_flag_only_matters_on_https(self):
        from polyglot_bug_hunter.net import Response
        resp = Response(url="https://x/", status=200,
                        headers={"set-cookie": "s=1; Path=/"})
        assert any("Secure" in f.title for f in passive.check_cookies(resp, "https://x/"))
        resp_http = Response(url="http://x/", status=200,
                             headers={"set-cookie": "s=1; Path=/"})
        assert not any("Secure" in f.title for f in passive.check_cookies(resp_http, "http://x/"))

    def test_cors_reflection_with_credentials(self, http, demo_server):
        r = http.get(demo_server.url.rstrip("/") + "/customer",
                     headers={"Origin": "https://evil.example"})
        found = passive.check_cors(r, r.url, http)
        assert any(f.severity.value == "high" for f in found), \
            "reflecting any origin + credentials is a high finding"

    def test_debug_leak_detected(self, http, demo_server):
        # a 500 with driver error text is exactly the shape of a debug leak
        r = http.get(demo_server.url.rstrip("/") + "/product?id='")
        found = passive.check_meta_tags(r, r.url)
        assert any("Debug information" in f.title for f in found)


class TestClassifyContract:
    def test_verdicts_are_from_a_closed_set(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/product"
        allowed = {"vulnerable", "suspicious", "clean", "blocked", "error", ""}
        for inj in probe(http, url, "id", "1"):
            assert inj.verdict in allowed

    def test_every_probe_has_a_signal_when_positive(self, http, demo_server):
        url = demo_server.url.rstrip("/") + "/product"
        for inj in probe(http, url, "id", "1"):
            if inj.verdict in ("vulnerable", "suspicious"):
                assert inj.signals, f"{inj.payload.label} was {inj.verdict} with no signal"
