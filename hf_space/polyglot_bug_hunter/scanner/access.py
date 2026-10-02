"""IDOR / broken access control. Boring to describe, expensive to get wrong.

The technique is deliberately shallow: find a parameter that looks like an
object reference, walk it by exactly one step, and compare. If ?id=1 and ?id=2
return different users with the same status code and no denial in between, you
have unauthenticated horizontal access to another object's data.

We request the neighbouring identifier ONCE. We don't enumerate 10000 IDs, we
don't write anything, and we never touch another real user's data beyond the
single field the app already chose to return to an anonymous visitor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Confidence, Cvss, Evidence, Finding, Modality, Severity
from ..net import Response, replace_param

ID_PARAM_RE = re.compile(
    r"^(id|.*_id|uuid|guid|key|doc|document|post|article|item|product|order|"
    r"ticket|user|account|profile|file|object|record|row|entity|case|task|"
    r"number|no|num|ref|slug|hash|token|uid|pid|cid|oid|sid|fid)$", re.I)

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
NUM_RE = re.compile(r"^\d{1,9}$")

# Fields that scream "this is somebody else's data, and I'm anonymous".
LEAKY_FIELDS = (
    "email", "e-mail", "phone", "address", "ssn", "passport", "dob", "birth",
    "balance", "salary", "iban", "credit", "card", "token", "apikey", "api_key",
    "password_hash", "last_login", "ip_address",
)

# Lines that look like a personal record in a rendered page.
PII_LINE_RE = re.compile(
    r"(?:[\w.+-]+@[\w-]+\.[\w.]+)"                     # email
    r"|(?:\+?\d[\d\s().-]{8,17}\d)"                     # phone-ish
    r"|(?:\b\d{4}[- ]\d{2}[- ]\d{2}\b)"                 # dob
    r"|(?:\b(?:balance|salary|iban|ssn)\b\s*[:=])",    # labelled field
    re.I)


@dataclass(slots=True)
class IdorResult:
    url: str
    param: str
    original: str
    probe_value: str = ""
    baseline: Response | None = None
    probe: Response | None = None
    signals: list[str] = field(default_factory=list)
    shared_fields: list[str] = field(default_factory=list)
    leaked_fields: list[str] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return bool(self.leaked_fields)


def looks_like_id(name: str) -> bool:
    return bool(ID_PARAM_RE.match(name.strip()))


def neighbours(value: str, count: int = 2) -> list[str]:
    """The next few identifiers, same shape as the original."""
    out: list[str] = []
    if UUID_RE.match(value):
        # step the last hex block so we stay in the app's id space
        try:
            tail = int(value.replace("-", "")[-8:], 16)
            for i in range(1, count + 1):
                nxt = tail + i
                hexed = f"{nxt:08x}"
                out.append(value.replace(value.replace("-", "")[-8:], hexed))
        except ValueError:
            pass
    elif NUM_RE.match(value):
        base = int(value)
        for i in range(1, count + 1):
            out.append(str(base + i))
    else:
        # opaque slug: try a sibling-ish guess, cheap and harmless
        if value.isalpha():
            for ch in ("b", "c"):
                out.append(value[:-1] + ch if len(value) > 1 else value + ch)
    return out


def identity_signature(body: str) -> set[str]:
    """Field names present in the response. Two objects with the same shape and
    different values is the whole IDOR story."""
    keys = set(re.findall(r"name=[\"']([\w-]{2,30})[\"']", body or ""))
    keys |= set(re.findall(r'"([a-z_][a-z0-9_]{2,30})"\s*:', body or "", re.I))
    keys |= set(re.findall(r"<dt[^>]*>\s*([A-Za-z ]{3,24})\s*</dt>", body or ""))
    return keys


def pii_hits(body: str, limit: int = 6) -> list[str]:
    out: list[str] = []
    for m in PII_LINE_RE.finditer(body or ""):
        frag = re.sub(r"\s+", " ", (body[max(0, m.start() - 40): m.end() + 40])).strip()
        if frag not in out:
            out.append(frag[:160])
        if len(out) >= limit:
            break
    return out


def analyze(http, url: str, param: str, original: str, budget: int = 2) -> IdorResult:
    """One parameter, one baseline, one or two neighbour ids."""
    result = IdorResult(url=url, param=param, original=original)
    result.baseline = http.get(replace_param(url, param, original))

    for candidate in neighbours(original, budget):
        try:
            probe = http.get(replace_param(url, param, candidate))
        except Exception:
            continue
        if not probe.body or probe.error:
            continue
        if probe.status in (401, 403, 404) and result.baseline.status not in (401, 403):
            result.signals.append(f"{param}={candidate} correctly denied (HTTP {probe.status})")
            continue

        a, b = result.baseline.body or "", probe.body or ""
        if a == b:
            continue

        sig_a, sig_b = identity_signature(a), identity_signature(b)
        shared = sorted(sig_a & sig_b)
        result.shared_fields = shared[:20]
        leaked = [f for f in pii_hits(b) if f not in a]
        result.leaked_fields = leaked[:6]
        result.probe_value = candidate
        result.probe = probe

        if leaked:
            result.signals.append(
                f"{param}={candidate} returned {result.probe.status} with personal "
                f"data that was not in the {param}={original} response")
            break
        if shared and len(sig_a & sig_b) >= 3:
            result.signals.append(
                f"same record shape ({len(shared)} shared fields: "
                f"{', '.join(shared[:4])}) with different values for "
                f"{param}={original} vs {param}={candidate}")
    return result


def idor_to_finding(r: IdorResult) -> Finding | None:
    if not r.vulnerable or not r.probe:
        return None
    high_risk = [f for f in r.leaked_fields
                 if any(k in f.lower() for k in ("email", "balance", "ssn", "card",
                                                "iban", "salary", "password", "token"))]
    sev = Severity.CRITICAL if high_risk else Severity.HIGH
    return Finding(
        title=f"IDOR: '{r.param}' returns another object's personal data",
        severity=sev,
        modality=Modality.TEXT,
        cvss=Cvss.build("N", "L", "N", "N", "U", "H", "H", "N"),
        owasp="A01:2021 - Broken Access Control",
        cwe="CWE-639",
        url=r.url,
        endpoint=r.url,
        parameter=r.param,
        confidence=Confidence.HIGH if high_risk else Confidence.MEDIUM,
        description=(
            f"An unauthenticated request for {r.param}={r.probe_value} returned HTTP "
            f"{r.probe.status} with content that differs from {r.param}={r.original} and "
            f"contains personal data. The server is not checking whether the caller "
            f"owns that object - it only checks whether they can reach the URL."
        ),
        impact=("Read (and often write) every record of every user in the system by "
                "incrementing one integer. This is the single most commonly exploited "
                "web bug in bug bounties."),
        remediation="Authorise every access server-side against the session owner. "
                    "Never rely on an unguessable id. Use opaque UUIDs *as well as* "
                    "real authorisation - UUIDs hide, they do not protect.",
        evidence=Evidence(
            request=(f"GET {r.url}?{r.param}={r.original}\n"
                     f"GET {r.url}?{r.param}={r.probe_value}   (no cookie, no auth)"),
            response_snippet=(r.probe.snippet(r.probe_value) or "")[:300]
                            or r.leaked_fields[0] if r.leaked_fields else "",
            proof="; ".join(r.signals),
            extra={"original": r.original, "probe": r.probe_value,
                   "baseline_status": r.baseline.status if r.baseline else None,
                   "probe_status": r.probe.status,
                   "shared_fields": r.shared_fields,
                   "leaked": r.leaked_fields},
        ),
        tags=["idor", "access-control", "unauthenticated", "owasp-a1"],
    )
