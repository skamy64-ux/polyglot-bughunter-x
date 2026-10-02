"""Scoring. CVSS v3.1 is the part of this project other people will integrate,
so it gets tested against an independent implementation rather than against my
memory of the spec.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from polyglot_bug_hunter.models import (
    Cvss,
    Finding,
    Modality,
    ScanReport,
    Severity,
    cvss_to_severity,
)

ROOT = Path(__file__).resolve().parents[1]


class TestCvssMath:
    # vectors with published scores from the CVSS v3.1 specification and NVD
    REFERENCE = {  # noqa: RUF012 - a class attribute is the pytest idiom here
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
        "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,   # Log4Shell
        "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
        "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        # NB: Heartbleed (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N -> 7.5) is already
        # listed above. A dict literal would silently keep the last duplicate,
        # which is how a test ends up asserting fewer cases than it reads like.
    }

    @pytest.mark.parametrize("vector,expected", sorted(REFERENCE.items()))
    def test_reference_vectors(self, vector, expected):
        m = dict(kv.split(":") for kv in vector.split("/"))
        got = Cvss.build(av=m["AV"], ac=m["AC"], pr=m["PR"], ui=m["UI"],
                         scope=m["S"], conf=m["C"], integ=m["I"], avail=m["A"])
        assert got.score == pytest.approx(expected, abs=0.05), f"{vector}: {got.score}"

    def test_vector_string_round_trips(self):
        c = Cvss.build(av="N", ac="L", pr="L", ui="R", scope="C",
                       conf="H", integ="L", avail="N")
        assert c.vector.startswith("CVSS:3.1/")
        assert c.vector.count("/") == 8
        for part in c.vector.split("/")[1:]:
            key, _, val = part.partition(":")
            assert key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
            assert len(val) == 1 and val in "NALPHCRUI"

    def test_exhaustive_sweep_is_monotonic_and_bounded(self):
        """Every vector in the space must land in [0, 10] and increase with impact."""
        combos = itertools.product("NALP", "LH", "NLH", "NR", "UC", "HNL", "HNL", "HNL")
        seen_max, seen_min = -1.0, 11.0
        for av, ac, pr, ui, sc, c, i, a in combos:
            s = Cvss.build(av=av, ac=ac, pr=pr, ui=ui, scope=sc,
                           conf=c, integ=i, avail=a).score
            assert 0.0 <= s <= 10.0
            assert round(s, 1) == s, "spec says one decimal place"
            seen_min, seen_max = min(seen_min, s), max(seen_max, s)
        assert seen_min == 0.0, "there must be a zero-impact vector"
        assert seen_max == 10.0, "there must be a 10.0 vector"

    def test_impact_increases_score(self):
        low = Cvss.build(conf="N", integ="N", avail="N").score
        mid = Cvss.build(conf="L", integ="L", avail="N").score
        high = Cvss.build(conf="H", integ="H", avail="H").score
        assert low < mid < high

    def test_difficulty_increases_score(self):
        """A real impact metric is required, or every variant scores 0.0."""
        base = {"conf": "L", "integ": "L", "avail": "L"}
        assert Cvss.build(ac="H", **base).score < Cvss.build(ac="L", **base).score
        assert Cvss.build(ui="R", **base).score < Cvss.build(ui="N", **base).score
        assert (Cvss.build(pr="H", **base).score
                < Cvss.build(pr="L", **base).score
                < Cvss.build(pr="N", **base).score)
        assert (Cvss.build(av="P", **base).score
                < Cvss.build(av="L", **base).score
                < Cvss.build(av="N", **base).score)

    @pytest.mark.parametrize("score,band", [
        (0.0, "info"), (0.1, "low"), (3.9, "low"), (4.0, "medium"),
        (6.9, "medium"), (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
    ])
    def test_severity_bands(self, score, band):
        assert cvss_to_severity(score).value == band

    def test_independent_implementation_agrees(self):
        """Cross-check 5000 random vectors against RedHatProductSecurity/cvss.

        Skipped when that package isn't installed - it is a development-only
        dependency and the reference vectors above are the real gate.
        """
        cvss_mod = pytest.importorskip("cvss", reason="pip install cvss to run this")
        import random

        random.seed(1337)
        mismatches = []
        for _ in range(5000):
            m = {"AV": random.choice("NALP"), "AC": random.choice("LH"),
                 "PR": random.choice("NLH"), "UI": random.choice("NR"),
                 "S": random.choice("UC"), "C": random.choice("HNL"),
                 "I": random.choice("HNL"), "A": random.choice("HNL")}
            vector = "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in m.items())
            expected = round(cvss_mod.CVSS3(vector).scores()[0], 1)
            got = Cvss.build(av=m["AV"], ac=m["AC"], pr=m["PR"], ui=m["UI"],
                            scope=m["S"], conf=m["C"], integ=m["I"],
                            avail=m["A"]).score
            if abs(got - expected) > 0.05:
                mismatches.append((vector, expected, got))
        assert not mismatches, f"{len(mismatches)} mismatches, first: {mismatches[0]}"

    def test_reference_table_has_no_silent_duplicates(self):
        """A dict literal drops duplicate keys without complaining."""
        assert len(self.REFERENCE) == 15, (
            "a dict literal drops duplicate keys silently, so this count is the "
            "only thing that notices one sneaks in")


class TestRiskScore:
    @staticmethod
    def _report(sev, n=1, conf=None):
        rep = ScanReport(target="t")
        rep.findings = [
            Finding(title=f"t{i}", severity=sev, modality=Modality.TEXT,
                    confidence=conf or __import__(
                        "polyglot_bug_hunter.models", fromlist=["Confidence"]).Confidence.HIGH,
                    cvss=Cvss.build())
            for i in range(n)
        ]
        return rep

    def test_empty_is_zero(self):
        assert ScanReport(target="t").risk_score == 0.0

    def test_monotonic_in_severity(self):
        scores = [self._report(s).risk_score for s in
                  (Severity.INFO, Severity.LOW, Severity.MEDIUM,
                   Severity.HIGH, Severity.CRITICAL)]
        assert scores == sorted(scores)
        assert scores[0] < scores[-1]

    def test_monotonic_in_count(self):
        a = self._report(Severity.HIGH, 1).risk_score
        b = self._report(Severity.HIGH, 5).risk_score
        assert b > a

    def test_saturates_below_one_hundred(self):
        rep = self._report(Severity.CRITICAL, 500)
        assert rep.risk_score == 100.0

    def test_one_critical_is_not_almost_a_hundred(self):
        """A single critical finding should not read like forty of them."""
        assert self._report(Severity.CRITICAL).risk_score < 30.0

    def test_confidence_lowers_the_score(self):
        from polyglot_bug_hunter.models import Confidence
        high = self._report(Severity.HIGH, 1, Confidence.HIGH).risk_score
        low = self._report(Severity.HIGH, 1, Confidence.LOW).risk_score
        assert low < high

    def test_counts_and_modality_breakdown(self):
        rep = ScanReport(target="t")
        rep.findings = [
            Finding(title="a", severity=Severity.HIGH, modality=Modality.TEXT, cvss=Cvss.build()),
            Finding(title="b", severity=Severity.LOW, modality=Modality.AUDIO, cvss=Cvss.build()),
            Finding(title="c", severity=Severity.HIGH, modality=Modality.TEXT, cvss=Cvss.build()),
        ]
        assert rep.counts() == {"critical": 0, "high": 2, "medium": 0, "low": 1, "info": 0}
        assert rep.by_modality() == {"text": 2, "audio": 1}
        assert rep.worst == Severity.HIGH

    def test_sorted_findings_puts_worst_first(self):
        rep = ScanReport(target="t")
        rep.findings = [
            Finding(title="low", severity=Severity.LOW, modality=Modality.TEXT, cvss=Cvss.build()),
            Finding(title="crit", severity=Severity.CRITICAL, modality=Modality.TEXT, cvss=Cvss.build()),
            Finding(title="high", severity=Severity.HIGH, modality=Modality.TEXT, cvss=Cvss.build()),
        ]
        assert [f.title for f in rep.sorted_findings()] == ["crit", "high", "low"]

    def test_report_is_json_serialisable(self):
        rep = ScanReport(target="https://x")
        rep.findings = [Finding(title="a", severity=Severity.HIGH,
                                modality=Modality.TEXT, cvss=Cvss.build())]
        reparsed = json.loads(rep.to_json())
        assert reparsed["target"] == "https://x"
        assert reparsed["findings"][0]["severity"] == "high"
        assert "fingerprint" in reparsed["findings"][0]
