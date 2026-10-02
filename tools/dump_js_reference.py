#!/usr/bin/env python3
"""Dump the Python reference behaviour to JSON for the JS cross-check.

`node tools/test_static_space.mjs` compares the JavaScript port against this
file. If the two ever disagree, the test fails - which is the only way a hand-
written port stays honest.

    python tools/dump_js_reference.py
    node tools/test_static_space.mjs
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from polyglot_bug_hunter import payloads as P  # noqa: E402
from polyglot_bug_hunter.demo_target import _simulate_query, _toy_template  # noqa: E402
from polyglot_bug_hunter.i18n import SUPPORTED, Translator, normalize  # noqa: E402
from polyglot_bug_hunter.models import Cvss, cvss_to_severity  # noqa: E402
from polyglot_bug_hunter.report.render import plural  # noqa: E402
from polyglot_bug_hunter.safety import FORBIDDEN_PAYLOAD_SUBSTRINGS  # noqa: E402
from polyglot_bug_hunter.scanner import text as text_mod  # noqa: E402

OUT = ROOT / "artifacts" / "js_reference.json"

# The same published vectors the pytest suite asserts on. Keys must be unique:
# a dict literal drops duplicates silently, which is how a test ends up checking
# fewer cases than it reads like. tests/test_scoring.py asserts this count.
REFERENCE = {
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L": 7.3,
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
    "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L": 5.6,
    "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
    "AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,
    "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
    "AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.7,
    "AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N": 0.0,
    "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H": 8.8,
    "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L": 6.3,
    "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
    "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
    "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
}


def parse_vector(vector: str) -> dict[str, str]:
    return dict(kv.split(":") for kv in vector.split("/"))


def cvss_of(m: dict[str, str]) -> float:
    return Cvss.build(av=m["AV"], ac=m["AC"], pr=m["PR"], ui=m["UI"],
                      scope=m["S"], conf=m["C"], integ=m["I"],
                      avail=m["A"]).score


def main() -> int:
    random.seed(1337)
    data: dict = {}

    # ---- CVSS ----------------------------------------------------------
    rnd = []
    for _ in range(5000):
        m = {"AV": random.choice("NALP"), "AC": random.choice("LH"),
             "PR": random.choice("NLH"), "UI": random.choice("NR"),
             "S": random.choice("UC"), "C": random.choice("HNL"),
             "I": random.choice("HNL"), "A": random.choice("HNL")}
        rnd.append({"m": m, "expected": cvss_of(m)})
    data["cvss"] = {
        "reference": [{"m": parse_vector(v), "expected": s}
                      for v, s in sorted(REFERENCE.items())],
        "random": rnd,
        "bands": {str(s): cvss_to_severity(float(s)).value
                  for s in (0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0)},
    }

    # ---- the SQL / template simulators ---------------------------------
    sim_inputs = [
        "1", "2", "abc", "' OR 1=1 -- ", "' OR '1'='1", "'PBHX7",
        "1' ORDER BY 99 -- -", "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -", "1 OR 1=1--", "",
        "'", '"', "1;DROP TABLE x", "0", "999", "-1", "1.5",
        "' UNION SELECT NULL,NULL,NULL -- ", "1' order by 3 -- ", "NULL",
    ]
    sim_inputs += [p.value for _, p in P.iter_all()
                   if p.vuln in ("sqli", "nosql-ldap")]
    seen: set[str] = set()
    rows = []
    for pid in sim_inputs:
        if pid in seen:
            continue
        seen.add(pid)
        outcome, r, _note = _simulate_query(pid)
        rows.append({"input": pid, "expected": {"outcome": outcome, "rows": r}})
    data["simulateQuery"] = rows
    data["simulateQueryAll"] = sorted(seen)

    tpl_inputs = [
        "hello {{ name }}", "a {{7*7}} b", "{{7*7}}", "{{8*8}}", "${7*7}",
        "<%= 7*7 %>", "{{7*'7'}}", "no tags here", "{{}}", "{{ 1 + 1 }}",
        "{{ 10 / 0 }}", "{{ 'abc' }}", "{{{7*7}}}", "x{{7*7}}{{8*8}}y",
        "{{a}}{{b}}", "plain text", "{{ 3 * 3 }}",
    ]
    data["toyTemplate"] = [{"input": t, "expected": _toy_template(t)}
                           for t in tpl_inputs]

    # ---- classify() verdicts against the bundled demo target ----------
    from polyglot_bug_hunter.config import ScanConfig
    from polyglot_bug_hunter.demo_target import DemoServer
    from polyglot_bug_hunter.net import Http
    from polyglot_bug_hunter.safety import ScanPolicy

    classify_rows = []
    with DemoServer() as srv:
        pol = ScanPolicy(authorization_confirmed=True, allow_private_network=True,
                         active_probing=True, allow_state_changing_methods=True,
                         rate_per_minute=9000, max_requests=100_000)
        http = Http(pol, ScanConfig())
        base = srv.url.rstrip("/")
        from polyglot_bug_hunter.net import replace_param
        from polyglot_bug_hunter.scanner.text import Injection

        for path, param, original in [("/product", "id", "1"),
                                      ("/render", "tpl", "hi"),
                                      ("/search", "q", "widget"),
                                      ("/redirect", "next", "/"),
                                      ("/profile", "u", "1"),
                                      ("/customer", "id", "1")]:
            bl = http.get(replace_param(f"{base}{path}", param, original))
            for p in P.for_value(param, original, 6):
                probe = http.get(replace_param(f"{base}{path}", param, p.value))
                inj = Injection(payload=p, param=param, baseline=bl, probe=probe)
                classify_rows.append({
                    "path": path, "param": param, "original": original,
                    "payload": {"label": p.label, "value": p.value,
                                "vuln": p.vuln, "polyglot": p.polyglot,
                                "confidence": p.confidence,
                                "owasp": p.owasp, "cwe": p.cwe},
                    "verdict": text_mod.classify(inj, bl),
                })
    data["classify"] = classify_rows

    # ---- payload routing ----------------------------------------------
    data["payloadCount"] = len(P.ALL_PAYLOADS)
    data["polyglotCount"] = sum(1 for p in P.ALL_PAYLOADS if p.polyglot)
    data["forbidden"] = list(FORBIDDEN_PAYLOAD_SUBSTRINGS)

    routing = []
    for name in ("id", "q", "next", "tpl", "file", "msg", "url", "cmd", "user",
                 "zzzz", "search", "redirect", "email", "order", "sort", "page",
                 "category", "lang", "token", "api_key", "host", "path", "name",
                 "comment", "title", "description", "code", "doc", "image", "avatar"):
        for budget in (4, 6, 10):
            routing.append({"name": name, "budget": budget,
                            "expected": [p.label for p in P.for_param(name, budget)]})
    data["routing"] = routing

    routing_value = []
    for name, value in (("id", "1"), ("next", "/"), ("q", "widget"),
                        ("tpl", "hi"), ("file", "/etc/passwd"),
                        ("url", "https://example.com/"), ("email", "a@b.co"),
                        ("page", "2"), ("msg", "hello"), ("host", "1.2.3.4")):
        routing_value.append({"name": name, "value": value, "budget": 6,
                              "expected": [p.label for p in P.for_value(name, value, 6)]})
    data["routingValue"] = routing_value
    data["routedNames"] = sorted({r["name"] for r in routing})

    # ---- i18n ----------------------------------------------------------
    en_keys = sorted(k for k in json.loads((ROOT / "locales" / "en.json")
                                          .read_text(encoding="utf-8"))
                     if not k.startswith("_meta"))
    locales = []
    for code in SUPPORTED:
        raw = json.loads((ROOT / "locales" / f"{code}.json").read_text(encoding="utf-8"))
        keys = sorted(k for k in raw if not k.startswith("_meta"))
        locales.append({"code": code, "keys": keys,
                        "missing": sorted(set(en_keys) - set(keys)),
                        "extra": sorted(set(keys) - set(en_keys))})
    data["locales"] = locales
    data["normalize"] = {t: normalize(t) for t in
                         ["ja-JP", "zh-TW", "ar-EG", "pt-BR", "in", "en-US",
                          "xx-YY", "ko-KR", "de-AT", "fr-CA", "id-ID", "hi", ""]}
    data["localeSample"] = {
        "ja": {"navScan": Translator("ja").get("nav.scan")},
        "ru": {"navScan": Translator("ru").get("nav.scan")},
    }

    # ---- report math ---------------------------------------------------
    def fsev(sev, conf="high", n=1):
        from polyglot_bug_hunter.models import Confidence, Finding, Modality, ScanReport, Severity
        rep = ScanReport(target="t")
        rep.findings = [
            Finding(title=f"t{i}", severity=Severity(sev), modality=Modality.TEXT,
                    confidence=Confidence(conf), cvss=Cvss.build())
            for i in range(n)
        ]
        return rep

    risk = []
    for sev in ("info", "low", "medium", "high", "critical"):
        for n in (1, 3, 10):
            risk.append({"findings": [{"severity": sev, "confidence": "high"}] * n,
                         "expected": fsev(sev, n=n).risk_score})
    risk.append({"findings": [], "expected": 0.0})
    risk.append({"findings": [{"severity": "high", "confidence": "low"}],
                 "expected": fsev("high", conf="low").risk_score})
    data["riskScore"] = risk
    data["worstOf"] = [
        {"findings": [{"severity": "low"}, {"severity": "critical"}], "expected": "critical"},
        {"findings": [{"severity": "medium"}, {"severity": "high"}], "expected": "high"},
        {"findings": [{"severity": "info"}], "expected": "info"},
        {"findings": [], "expected": "info"},
    ]
    data["plural"] = {n: plural(n, "finding") for n in (0, 1, 2, 5)}

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"reference dumped -> {OUT}  ({OUT.stat().st_size // 1024} KB)")
    print(f"  cvss vectors   : {len(data['cvss']['reference'])} reference + {len(data['cvss']['random'])} random")
    print(f"  simulateQuery  : {len(data['simulateQuery'])}")
    print(f"  toyTemplate    : {len(data['toyTemplate'])}")
    print(f"  classify       : {len(data['classify'])}")
    print(f"  routing        : {len(data['routing'])} forParam + {len(data['routingValue'])} forValue")
    print(f"  locales        : {len(data['locales'])}")
    print(f"  riskScore      : {len(data['riskScore'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
