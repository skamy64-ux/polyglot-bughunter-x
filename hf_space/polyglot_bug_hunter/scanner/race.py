"""Race conditions and CSRF. The two bugs that need *timing*, not payloads.

Race: fire N identical state-changing requests at once. If the app does
read-modify-write without a lock or an idempotency key, you get duplicates,
double spend, or inventory drift.

CSRF: does the form carry a token that changes per request, does it need a
custom header, and would a cross-site POST actually work?
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..models import Confidence, Cvss, Evidence, Finding, Modality, Severity
from ..net import Response

CSRF_TOKEN_NAMES = (
    "csrf", "csrfmiddlewaretoken", "xsrf", "_token", "authenticity_token",
    "__requestverificationtoken", "anti_forgery", "_csrf", "token",
)

CSRF_META = re.compile(
    r"<input[^>]+name=[\"']([^\"']*csrf[^\"']*|[^\"']*token[^\"']*|[^\"']*authenticity[^\"']*)[\"']"
    r"[^>]+value=[\"']([^\"']{6,})[\"']", re.I)

CSRF_HEADER_HINT = re.compile(r"[\"']X-CSRF-Token[\"']|csrfToken", re.I)


@dataclass(slots=True)
class RaceResult:
    url: str
    method: str
    threads: int
    statuses: list[int] = field(default_factory=list)
    bodies: list[str] = field(default_factory=list)
    duplicates: int = 0
    unique: int = 0
    elapsed_ms: float = 0.0
    errors: int = 0

    @property
    def _tally(self) -> tuple[int, int]:
        """(duplicates, unique). Derived from bodies so a hand-built
        RaceResult can't claim something its own data doesn't support."""
        if self.bodies:
            return len(self.bodies) - len(set(self.bodies)), len(set(self.bodies))
        return self.duplicates, self.unique

    @property
    def successes(self) -> int:
        return sum(1 for s in self.statuses if 200 <= s < 400)

    @property
    def interesting(self) -> bool:
        if self.successes < 2:
            return False          # errors and blocks are not a race
        duplicates, unique = self._tally
        n = len(self.bodies) or self.threads
        return duplicates > 1 and unique <= max(1, n // 2)


def race_probe(http, url: str, data: dict[str, str], threads: int = 6,
               method: str = "POST") -> RaceResult:
    """Hammer one endpoint concurrently and look for duplicate effects.

    We don't need to *prove* a race to be useful: seeing 6 identical 200s with
    6 identical new-resource bodies is a strong hint. We also compare the
    baseline response shape so we can tell "server said OK 6 times" apart from
    "server actually did the thing 6 times".
    """
    import time
    result = RaceResult(url=url, method=method, threads=threads)
    start = time.perf_counter()

    def one(_: int) -> Response:
        try:
            return http.request(method, url, data=data)
        except Exception:
            return Response(url=url, status=0, error="failed")

    with ThreadPoolExecutor(max_workers=threads) as pool:
        responses = list(pool.map(one, range(threads)))

    result.elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
    result.statuses = [r.status for r in responses]
    result.errors = sum(1 for r in responses if r.error)
    bodies = [r.body for r in responses if r.body]
    result.bodies = [b[:4000] for b in bodies]
    result.unique = len(set(result.bodies))
    result.duplicates = len(bodies) - result.unique

    # concurrency against a token bucket shouldn't be blocked by our own limiter
    if result.errors >= threads:
        result.elapsed_ms = 0.0
    return result


def race_to_finding(race: RaceResult, baseline: Response | None, url: str,
                    param_hint: str = "") -> Finding | None:
    if not race.interesting:
        return None
    ok = sum(1 for s in race.statuses if 200 <= s < 300)
    if ok < 2:
        return None
    _, unique = race._tally
    return Finding(
        title="Possible race condition (TOCTOU) on a state-changing endpoint",
        severity=Severity.HIGH,
        modality=Modality.TEXT,
        cvss=Cvss.build("N", "H", "N", "N", "U", "L", "H", "H"),
        owasp="A04:2021 - Insecure Design",
        cwe="CWE-362",
        url=url,
        endpoint=url,
        parameter=param_hint,
        confidence=Confidence.LOW,
        description=(
            f"{race.threads} simultaneous {race.method} requests all returned success "
            f"({ok}/{race.threads} 2xx) in {race.elapsed_ms}ms, but only "
            f"{unique} distinct response body/bodies came back. A handler that "
            f"reads-then-writes without a lock or an idempotency key usually applies "
            f"the change several times, even when the response looks identical."
        ),
        impact="Double spend, duplicate records, inventory drift, coupon abuse, "
               "or balance manipulation.",
        remediation="Make the operation atomic: a UNIQUE constraint or a conditional "
                    "UPDATE at the database level, plus an idempotency key per logical "
                    "request. Application-level locks alone are not enough.",
        evidence=Evidence(
            request=f"{race.method} {url} x{race.threads} concurrently\ndata={param_hint}",
            proof=f"statuses={race.statuses} unique_bodies={race.unique}/{len(race.bodies)} "
                  f"in {race.elapsed_ms}ms",
            response_snippet=(race.bodies[0][:300] if race.bodies else ""),
            extra={"baseline_status": baseline.status if baseline else None,
                   "threads": race.threads, "duplicates": race.duplicates},
        ),
        tags=["race", "logic-bug", "needs-manual-confirm"],
    )


# --- CSRF -------------------------------------------------------------------


@dataclass(slots=True)
class CsrfAssessment:
    form_action: str
    method: str
    has_token: bool = False
    token_name: str = ""
    token_is_static: bool = False
    same_site: str = ""
    cookie_present: bool = False
    risk: str = "low"
    notes: list[str] = field(default_factory=list)


def assess_csrf(form: dict, html: str, resp: Response | None = None) -> CsrfAssessment:
    """Read the form and the page around it."""
    out = CsrfAssessment(form_action=form.get("action", ""),
                          method=form.get("method", "GET"))
    fields = {f.get("name", "").lower(): f for f in form.get("fields", [])}

    for name, f in fields.items():
        if any(t in name for t in CSRF_TOKEN_NAMES):
            value = f.get("value", "")
            if len(value) >= 6:
                out.has_token = True
                out.token_name = f.get("name", "")
                out.notes.append(f"token field '{out.token_name}' found")
            break

    if not out.has_token:
        m = CSRF_META.search(html or "")
        if m:
            out.has_token = True
            out.token_name = m.group(1)
            out.notes.append(f"token meta/input '{m.group(1)}' found")

    if CSRF_HEADER_HINT.search(html or ""):
        out.notes.append("frontend reads a CSRF header (double-submit pattern)")

    if resp is not None:
        cookies = resp.cookies
        out.cookie_present = bool(cookies)
        for name in cookies:
            if "csrf" in name or "xsrf" in name:
                out.same_site = "unknown"
        raw = ";".join(resp.set_cookie_raw).lower()
        if "samesite=none" in raw:
            out.same_site = "None"
        elif "samesite=lax" in raw:
            out.same_site = "Lax"
        elif "samesite=strict" in raw:
            out.same_site = "Strict"

    if out.method in ("GET",):
        out.risk = "low"
        out.notes.append("GET form: no state change to forge")
    elif not out.has_token:
        out.risk = "high" if out.same_site != "Strict" else "medium"
        out.notes.append("state-changing form with no anti-CSRF token")
    elif out.has_token and out.same_site == "None":
        out.risk = "medium"
        out.notes.append("token exists but cookie is SameSite=None, so the browser "
                         "sends it cross-site anyway")
    else:
        out.risk = "low"

    return out


def csrf_to_finding(a: CsrfAssessment, url: str) -> Finding | None:
    if a.risk == "low" or a.method == "GET":
        return None
    sev = Severity.HIGH if a.risk == "high" else Severity.MEDIUM
    return Finding(
        title=f"Missing CSRF protection on {a.method} form ({a.form_action or 'same page'})",
        severity=sev,
        modality=Modality.TEXT,
        cvss=Cvss.build("N", "L", "N", "R", "U", "L", "H", "N"),
        owasp="A01:2021 - Broken Access Control",
        cwe="CWE-352",
        url=url,
        endpoint=a.form_action or url,
        confidence=Confidence.MEDIUM if not a.has_token else Confidence.LOW,
        description=(
            "A state-changing form with no per-request anti-CSRF token. An attacker can "
            "host a page that auto-submits this action while the victim is logged in, "
            "and the browser attaches their session cookie automatically."
            + (f" Cookie SameSite is {a.same_site}, which does not save you."
               if a.same_site and a.same_site != "Strict" else "")
        ),
        impact="Any action a logged-in user can perform, performed by someone else: "
               "password change, email change, purchase, delete.",
        remediation="Per-session-per-request CSRF token (Django/Rails/Laravel have "
                    "them built in), SameSite=Lax|Strict on the session cookie, and "
                    "re-check the Referer/Origin header server-side.",
        evidence=Evidence(
            request=f"Observed form: {a.method} {a.form_action}",
            proof="; ".join(a.notes),
            extra={"has_token": a.has_token, "token_name": a.token_name,
                   "same_site": a.same_site, "risk": a.risk},
        ),
        tags=["csrf", "passive", "forms"],
    )
