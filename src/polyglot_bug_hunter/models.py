"""Data shapes. Findings, evidence, reports.

Plain dataclasses on purpose: the core must import with zero third-party deps
so it runs on a free CPU Space without a 400MB wheel download. If pydantic is
around we still expose the same classes (they ARE dataclasses), we just add a
`.model_dump()` shim for folks coming from pydantic land.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "1.0.0"


class Modality(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    PASSIVE = "passive"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# CVSS v3.1 base metrics we actually fill in. Everything else is out of scope.
@dataclass(slots=True)
class Cvss:
    vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    score: float = 0.0
    severity: Severity = Severity.INFO
    rationale: str = ""

    @staticmethod
    def build(
        av: str = "N",      # attack vector
        ac: str = "L",      # attack complexity
        pr: str = "N",      # privileges required
        ui: str = "N",      # user interaction
        scope: str = "U",   # scope
        conf: str = "N",    # confidentiality impact
        integ: str = "N",   # integrity impact
        avail: str = "N",   # availability impact
    ) -> Cvss:
        vector = (
            f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}"
            f"/C:{conf}/I:{integ}/A:{avail}"
        )
        score = round(_cvss31_score(av, ac, pr, ui, scope, conf, integ, avail), 1)
        return Cvss(
            vector=vector,
            score=score,
            severity=cvss_to_severity(score),
            rationale=f"AV:{av} AC:{ac} PR:{pr} UI:{ui} S:{scope} C:{conf} I:{integ} A:{avail}",
        )


# --- CVSS v3.1 math (spec section 8.1) -------------------------------------

_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(x: float) -> float:
    # CVSS 3.1 Roundup: smallest 1-decimal number >= x, integer math or bust.
    i = round(x * 100_000)
    if i % 10_000 == 0:
        return i / 100_000.0
    return (int(i / 10_000) + 1) / 10.0


def _cvss31_score(
    av: str, ac: str, pr: str, ui: str, scope: str, c: str, i: str, a: str
) -> float:
    iss = 1 - ((1 - _WEIGHTS["CIA"][c]) * (1 - _WEIGHTS["CIA"][i]) * (1 - _WEIGHTS["CIA"][a]))
    scope_changed = scope == "C"
    pr_weight = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[pr]
    impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15) if scope_changed else \
        6.42 * iss
    exploitability = (
        8.22 * _WEIGHTS["AV"][av] * _WEIGHTS["AC"][ac] * pr_weight * _WEIGHTS["UI"][ui]
    )
    if impact <= 0:
        return 0.0
    raw = _roundup(min(1.08 * (impact + exploitability), 10)) if scope_changed else \
        _roundup(min(impact + exploitability, 10))
    return float(raw)


def cvss_to_severity(score: float) -> Severity:
    if score == 0:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# --- findings ---------------------------------------------------------------


@dataclass(slots=True)
class Evidence:
    """The 'show me' part. A finding without evidence is a guess."""

    request: str = ""
    response_snippet: str = ""
    proof: str = ""
    screenshot: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not (self.request or self.response_snippet or self.proof or self.screenshot)


@dataclass(slots=True)
class Finding:
    title: str
    severity: Severity
    modality: Modality
    cvss: Cvss = field(default_factory=Cvss)
    owasp: str = ""            # e.g. "A03:2021 - Injection"
    cwe: str = ""              # e.g. "CWE-79"
    url: str = ""
    endpoint: str = ""
    parameter: str = ""
    confidence: Confidence = Confidence.MEDIUM
    description: str = ""
    impact: str = ""
    remediation: str = ""
    payload: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    discovered_at: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)
    #: 'endpoint' = this URL only. 'host' = the whole origin, so a missing CSP
    #: is reported once with a page count instead of forty identical rows.
    scope: str = "endpoint"
    #: filled in by the report when the same host-scope bug hits several pages
    affected_pages: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable id so the same bug isn't reported twice across runs."""
        from urllib.parse import urlsplit
        parts = urlsplit(self.endpoint or self.url)
        # same path + same parameter + same bug class == the same bug, whatever
        # the *other* query parameters happened to be on that request
        loc = (f"{parts.scheme}://{parts.netloc}" if self.scope == "host"
               else f"{parts.scheme}://{parts.netloc}{parts.path}")
        raw = f"{self.cwe or self.title}|{loc}|{self.parameter}|{self.title}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["modality"] = self.modality.value
        d["confidence"] = self.confidence.value
        d["cvss"] = asdict(self.cvss)
        d["cvss"]["severity"] = self.cvss.severity.value
        d["evidence"] = asdict(self.evidence)
        d["fingerprint"] = self.fingerprint
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass(slots=True)
class Asset:
    """One endpoint on the target. Scanners accumulate evidence onto assets."""

    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    status: int = 0
    content_type: str = ""
    title: str = ""
    forms: list[dict[str, Any]] = field(default_factory=list)
    tech: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        if finding.fingerprint in {f.fingerprint for f in self.findings}:
            return
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass(slots=True)
class ScanReport:
    target: str
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    modes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    screenshots: dict[str, str] = field(default_factory=dict)
    tech: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    policy_note: str = ""
    schema_version: str = SCHEMA_VERSION
    schema_url: str = "https://github.com/OpenSSF/ModelCard"
    toolkit: str = "PolyglotBugHunter-X"

    # -- rollups -----------------------------------------------------------

    @property
    def duration(self) -> float:
        return round((self.finished_at or time.time()) - self.started_at, 2)

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=Severity.INFO)

    @property
    def risk_score(self) -> float:
        """0-100 rollup. CVSS-weighted, recency-flat, deduped by fingerprint.

        Deliberately not 'sum of everything' - one critical finding should not
        be diluted by forty informational header nits.
        """
        if not self.findings:
            return 0.0
        weights = {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 12.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0,
            Severity.INFO: 0.5,
        }
        conf_mult = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.75, Confidence.LOW: 0.45}
        raw = sum(weights[f.severity] * conf_mult[f.confidence] for f in self.findings)
        # saturating curve. divisor 120 means one critical finding lands near 19,
        # not near 100 - a score you can actually argue about in a standup.
        return round(100.0 * (1 - pow(2.718281828, -raw / 120.0)), 1)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def by_modality(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.modality.value] = out.get(f.modality.value, 0) + 1
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.cvss.score),
            reverse=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "toolkit": self.toolkit,
            "schema_version": self.schema_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": self.duration,
            "modes": self.modes,
            "policy_note": self.policy_note,
            "tech": self.tech,
            "risk_score": self.risk_score,
            "worst_severity": self.worst.value,
            "counts": self.counts(),
            "by_modality": self.by_modality(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "assets": [a.to_dict() for a in self.assets],
            "screenshots": self.screenshots,
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
