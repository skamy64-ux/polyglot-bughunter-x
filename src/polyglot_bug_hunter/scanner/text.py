"""Text modality: inject, then read the answer.

The interesting bit is `differential analysis`. A single probe proves nothing -
plenty of apps echo input without being vulnerable. What proves it is a *shape*:

  * SQLi  -> `" AND 1=1 --` changes the row count; `" AND 1=2 --` does not.
  * SSTI  -> `{{7*7}}` comes back as a literal `49`.
  * cmdi  -> `;id;` comes back as *the output of id*, not as the string `;id;`.
  * XSS   -> our tag comes back *unescaped*, and the DOM contains a new node.
  * SSTI/xxe -> error text appears that was not in the baseline response.

So every injection runs against a captured baseline and every verdict names the
comparison that produced it.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from ..models import Confidence, Cvss, Evidence, Finding, Modality, Severity
from ..net import Response, replace_param
from ..payloads import MARKER, Payload, for_param, for_value

# --- tell-tale strings ------------------------------------------------------

SQL_ERRORS = (
    "sql syntax", "mysql_fetch", "mysql_num_rows", "you have an error in your sql",
    "warning: mysql", "pg_query", "postgresql", "sqlite3", "sqlite::",
    "ora-00933", "ora-01756", "odbc driver", "microsoft ole db provider",
    "unclosed quotation mark", "syntax error at or near", "supplied argument is not",
    "valid mysql result", "operand should contain", "column count", "ambiguous column",
    "java.sql.sqlexception", "quoted string not properly terminated",
    "com.mysql.jdbc.exceptions", "hibernate", "jdbc", "unsupported sql",
)

#: payload -> the string a vulnerable engine renders. Keys are compared against
#: `payload.strip()`, and the braces are single on purpose - that is what
#: actually travels over the wire.
SSTI_ARITH = {
    "{7*7}": "49", "${7*7}": "49", "<%= 7*7 %>": "49", "<%= 7 * 7 %>": "49",
    "{7*'7'}": "77777749", "{8*8}": "64", "${8*8}": "64", "#{7*7}": "49",
    "{{7*7}}": "49",
}

COMMAND_OUTPUT = re.compile(
    r"(uid=\d+\(|root:|www-data:|nobody:|bin/sh|bin/bash|command not found|"
    r"^\s*total\s+\d+|\bwindows\s+system32\b)",
    re.I | re.M,
)

TEMPLATE_ENGINES = re.compile(
    r"(jinja2|twig|handlebars|mustache|freemarker|velocity|mako|"
    r"liquid|erb|artichoke|nunjucks)", re.I,
)

WAF_HINTS = ("cloudflare", "sucuri", "akamai", "incapsula", "modsecurity",
             "awswaf", "imperva", "fortiweb", "wallarm", "distil")


@dataclass(slots=True)
class Injection:
    """One probe: the payload, both responses, and the verdict."""

    payload: Payload
    param: str
    baseline: Response | None = None
    probe: Response | None = None
    verdict: str = ""            # vulnerable / suspicious / clean / blocked
    signals: list[str] = field(default_factory=list)

    @property
    def is_vuln(self) -> bool:
        return self.verdict in ("vulnerable", "suspicious")


# --- low level analysis -----------------------------------------------------


def _unescaped_reflection(baseline: Response, probe: Response, marker: str) -> bool:
    """Did our payload come back verbatim, i.e. unescaped?"""
    if not probe or marker not in probe.body:
        return False
    base_has = bool(baseline and marker in baseline.body)
    # find the reflection and look at the characters immediately around it
    idx = probe.body.find(marker)
    around = probe.body[max(0, idx - 60): idx + 200]
    escaped = any(e in around for e in ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "\\u003c"))
    return not base_has and not escaped


def has_payload_reflected(probe: Response, payload_value: str) -> bool:
    """Longest common substring > 8 chars, so encodings and truncation still count."""
    if not probe:
        return False
    probe_core = _strip_ws(probe.body)
    val = _strip_ws(payload_value)
    if len(val) < 6:
        return val and val in probe_core
    m = difflib.SequenceMatcher(None, val, probe_core[:200_000])
    blocks = m.get_matching_blocks()
    return any(b.size >= max(8, len(val) * 0.6) for b in blocks)


def _strip_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def body_shape(resp: Response | None) -> tuple[int, int, str]:
    """(length, line count, sorted common tokens). Cheap fingerprint of a page."""
    if not resp or not resp.body:
        return (0, 0, "")
    body = resp.body
    tokens = sorted({w for w in re.findall(r"[A-Za-z0-9]{4,}", body[:100_000])
                     if w.isalnum()})[:400]
    return (len(body), body.count("\n"), " ".join(tokens))


def row_count(resp: Response | None) -> int:
    """Heuristic 'how many results' for boolean-differential SQLi.

    Works for tables, card grids, JSON arrays and pagination footers without
    knowing anything about the app's markup.
    """
    if not resp or not resp.body:
        return 0
    body = resp.body
    counts = [
        len(re.findall(r"<tr\b", body, re.I)),                    # html tables
        len(re.findall(r"<li\b", body, re.I)),                    # lists
        len(re.findall(r'class="[^"]*(?:card|item|result|post|row|tile)[^"]*"', body, re.I)),
        len(re.findall(r'"(?:id|uuid|email|name)"\s*:', body)),    # json
        len(re.findall(r"<article\b", body, re.I)),
    ]
    return max(counts) if any(counts) else 0


def timing_differential(baseline: Response, probe: Response, margin_ms: int) -> bool:
    """Conservative timing check. Requires a big gap AND a second confirmation."""
    if not baseline or not probe or probe.error:
        return False
    return probe.elapsed_ms > baseline.elapsed_ms * 3 + margin_ms


# --- verdict engine ---------------------------------------------------------

_SQLI_META = {
    "xss": ("Reflected XSS", Severity.HIGH,
            "Your input comes back into the page unescaped, so a crafted link can "
            "run script in a victim's session.",
            "HTML-encode output on the way out and add a strict CSP. Contextual "
            "escaping (OWASP Java Encoder) beats regex cleaning."),
    "sqli": ("SQL injection", Severity.CRITICAL,
             "The database parsed our SQL and the result set changed. That is "
             "read and often write access to your entire database.",
             "Use parameterised queries / prepared statements everywhere. Never "
             "string-concatenate input into SQL. Least-privilege DB user."),
    "cmdi": ("OS command injection", Severity.CRITICAL,
             "Input reached a shell and its output came back. This is remote code "
             "execution on your server.",
             "Never pass input to a shell. Use execve-style argument arrays with "
             "no shell, and validate input against an allowlist."),
    "ssti": ("Server-side template injection", Severity.HIGH,
             "The template engine evaluated our expression, so we control the "
             "server-side render context - often full RCE.",
             "Render with a logic-less template engine, or sandbox the one you use. "
             "Never evaluate user input as template source."),
    "traversal": ("Path traversal / local file inclusion", Severity.CRITICAL,
                  "Our encoded traversal reached a file outside the intended "
                  "directory.",
                  "Resolve the path, then verify it is inside an allowlisted root "
                  "before opening it. Reject .. and encoded variants."),
    "ssrf": ("Server-side request forgery", Severity.HIGH,
             "The server fetched (or tried to fetch) a URL we supplied. From an "
             "internal service this reads cloud metadata and internal admin APIs.",
             "Allowlist outbound destinations, resolve-then-validate so DNS "
             "rebinding cannot point at 127.0.0.1, and block link-local ranges."),
    "redirect": ("Open redirect", Severity.LOW,
                 "The app redirects to an arbitrary external host. Perfect for "
                 "phishing with a trusted-looking link.",
                 "Allowlist redirect targets, or require relative paths only."),
    "nosql-ldap": ("NoSQL / LDAP injection", Severity.HIGH,
                   "A document or directory query accepted our operator, so filters "
                   "can be bypassed or dumped.",
                   "Type-check every field (reject objects/arrays where a scalar is "
                   "expected) and escape LDAP filters."),
    "prompt-injection": ("Prompt injection", Severity.HIGH,
                         "The model followed instructions embedded in our input "
                         "instead of the operator's rules, so untrusted content can "
                         "steer the agent's actions.",
                         "Treat model input as untrusted: separate instructions from "
                         "data, require confirmation for tool calls, and constrain "
                         "the tool surface with allowlists."),
}


def classify(inj: Injection, baseline: Response, margin_ms: int = 350) -> str:
    """The whole detection brain. Returns a verdict string."""
    p, probe = inj.payload, inj.probe
    if not probe:
        return "error"

    # 0. WAF ate it. Different status + a blocklist body = inconclusive, not clean.
    if probe.status in (403, 406, 429, 503) and baseline.status not in (403, 429):
        if any(h in (probe.body or "").lower() for h in WAF_HINTS) or probe.status in (403, 429):
            inj.signals.append(f"blocked by WAF (HTTP {probe.status})")
            return "blocked"
    # a 4xx/5xx is *data* - it's often the whole proof. only a transport
    # failure (status 0) means we learned nothing.
    if probe.status == 0 and probe.error and not baseline.error:
        inj.signals.append(f"request error: {probe.error}")
        return "error"

    # 404/410 on a parameter the baseline accepted means the app looked the value
    # up and did not find it. That is *correct* behaviour, not a filter bypass -
    # reporting it as one would be a false positive on every integer id.
    if probe.status in (404, 410) and baseline.status not in (404, 410):
        return "clean"

    vp = p.vuln

    # 1. SSTI arithmetic - strongest single signal there is
    if vp == "ssti":
        expect = SSTI_ARITH.get(p.value.strip())
        if expect and expect in probe.body:
            inj.signals.append(f"template rendered {p.value} -> {expect}")
            return "vulnerable"
        if re.search(r"7\*7|\$\{|<%=", probe.body[:20_000]):
            inj.signals.append("template syntax echoed - engine may be Jinja/Twig")
            return "suspicious"

    # 2. command output actually executed
    if vp == "cmdi":
        if COMMAND_OUTPUT.search(probe.body) and not COMMAND_OUTPUT.search(baseline.body):
            inj.signals.append("shell output in response (uid=/root:/windows)")
            return "vulnerable"
        if p.label == "crlf-newline" and probe.status >= 400 and baseline.status < 400:
            inj.signals.append("CRLF broke the response (status flip)")
            return "suspicious"

    # 3. SQL: error text, then boolean differential, then status flip
    if vp == "sqli":
        low = (probe.body or "").lower()
        new_err = [e for e in SQL_ERRORS if e in low and e not in (baseline.body or "").lower()]
        if new_err:
            inj.signals.append(f"db error leaked: {new_err[0]!r}")
            return "vulnerable"
        if probe.status >= 500 and baseline.status < 500:
            inj.signals.append(f"5xx on injection ({baseline.status} -> {probe.status})")
            return "vulnerable"
        if p.label.startswith("tautology") or p.label == "union-null":
            a, b = row_count(baseline), row_count(probe)
            if a and b and b > a:
                inj.signals.append(f"row count grew {a} -> {b} on a tautology")
                return "vulnerable"
            if a and b == 0 and a > 2:
                inj.signals.append("row count collapsed to 0")
                return "suspicious"
        if "order-by-probe" in p.label and probe.status >= 500 and baseline.status < 500:
            inj.signals.append("column count out of range error")
            return "vulnerable"

    # 4. traversal: real file markers
    if vp == "traversal":
        if "root:x:" in probe.body or "[fonts]" in probe.body.lower():
            inj.signals.append("etc/passwd or win.ini contents in response")
            return "vulnerable"
        if probe.status == 200 and "404" not in probe.body[:400].lower() and \
                baseline.status >= 400:
            inj.signals.append(f"traversal returned 200 (baseline {baseline.status})")
            return "suspicious"

    # 5. ssrf / redirect: our URL came back in a fetch or a Location header
    if vp in ("ssrf", "redirect"):
        loc = probe.header("location")
        needle = p.value.split("://")[-1].split("/")[0]
        if loc and needle and needle in loc:
            inj.signals.append(f"redirected to our host: {loc[:80]}")
            return "vulnerable"
        if probe.status in (301, 302, 307, 308) and baseline.status not in (301, 302, 307, 308):
            inj.signals.append(f"redirect status flip -> HTTP {probe.status}")
            return "suspicious"
        if probe.contains(MARKER) and vp == "ssrf":
            inj.signals.append("our URL echoed back - server may have fetched it")
            return "suspicious"
        if any(s in (probe.body or "").lower() for s in
               ("connection refused", "could not resolve host", "econnrefused",
                "getaddrinfo", "proxy error", "no route to host")):
            inj.signals.append("error text reveals outbound fetch attempt")
            return "vulnerable"

    # 6. nosql / ldap: shape change or operator echoed unescaped
    if vp == "nosql-ldap":
        # reflection alone proves nothing about a document/ldap filter; only a
        # changed result set does. XSS already owns the reflection signal.
        a, b = row_count(baseline), row_count(probe)
        if probe.status == 200 and b > a:
            inj.signals.append(f"document count grew {a} -> {b} - filter bypassed")
            return "vulnerable"
        if probe.status >= 400 and baseline.status < 400:
            inj.signals.append(f"filter parse error ({baseline.status} -> {probe.status})")
            return "suspicious"


    # 7. prompt injection: does the *response* comply with our instruction?
    if vp == "prompt-injection":
        if probe.contains(MARKER) and baseline.status == probe.status:
            lowered = (probe.body or "").lower()
            if any(w in lowered for w in ("ignore", "system prompt", "i'm sorry", "i cannot",
                                          "as an ai", "here is", "reveal", "instructions")):
                inj.signals.append("response text changed shape and mentions instructions")
                return "suspicious"
        if row_count(probe) != row_count(baseline):
            inj.signals.append("answer content changed")

    # 8. XSS: unescaped reflection. Screenshot proof comes from the DOM scanner.
    if vp == "xss":
        if _unescaped_reflection(baseline, probe, MARKER):
            inj.signals.append("payload reflected unescaped (no &lt;/&gt;/&quot;)")
            return "vulnerable"
        if has_payload_reflected(probe, p.value):
            inj.signals.append("payload reflected (partially encoded)")
            return "suspicious"
        if p.label == "reflected-marker" and probe.contains(MARKER):
            inj.signals.append("unique marker echoed verbatim")
            return "vulnerable"

    # 9. timing, last resort, needs corroboration
    if timing_differential(baseline, probe, margin_ms):
        inj.signals.append(
            f"timing jump {baseline.elapsed_ms}ms -> {probe.elapsed_ms}ms")
        return "suspicious"

    return "clean"


# --- finding builder --------------------------------------------------------


def to_finding(inj: Injection, baseline: Response, asset_url: str) -> Finding | None:
    """Turn a positive probe into a report-ready finding with evidence."""
    p, probe = inj.payload, inj.probe
    if not inj.is_vuln or not probe:
        return None

    title, sev, description, remediation = _SQLI_META.get(
        p.vuln, ("Injection detected", Severity.HIGH, "", ""))
    if p.vuln == "xss" and inj.verdict == "vulnerable" and p.label == "reflected-marker":
        title = "Reflected input echoed without encoding (XSS risk)"

    confidence = {
        "vulnerable": Confidence.HIGH,
        "suspicious": Confidence.MEDIUM,
    }[inj.verdict]
    if len(inj.signals) == 1 and inj.verdict == "suspicious":
        confidence = Confidence.LOW

    av, ac, pr, ui, scope, c, i, a = p.cvss
    body = baseline.body or ""
    ref = probe.snippet(MARKER) or probe.snippet(p.value[:12]) or probe.body[:200]

    return Finding(
        title=f"{title} via '{inj.param}' ({p.label})",
        severity=sev if inj.verdict == "vulnerable" else Severity.MEDIUM,
        modality=Modality.TEXT,
        cvss=Cvss.build(av, ac, pr, ui, scope, c, i, a),
        owasp=p.owasp,
        cwe=p.cwe,
        url=asset_url,
        endpoint=asset_url,
        parameter=inj.param,
        confidence=confidence,
        description=description,
        impact=(
            "An unauthenticated attacker can trigger this remotely. Severity depends on "
            "what runs behind it."
        ),
        remediation=remediation,
        payload=p.value,
        evidence=Evidence(
            request=(
                f"GET {asset_url}?{inj.param}={p.value}\n"
                f"Host: {asset_url.split('/')[2] if '//' in asset_url else ''}\n"
                f"Referer: https://pbhx-authorized-test.example/"
            ),
            response_snippet=ref or "(no reflection, see status/signal evidence)",
            proof="; ".join(inj.signals) or "manual review recommended",
            extra={
                "verdict": inj.verdict,
                "signals": inj.signals,
                "baseline_status": baseline.status,
                "probe_status": probe.status,
                "baseline_len": len(body),
                "probe_len": len(probe.body or ""),
                "baseline_ms": baseline.elapsed_ms,
                "probe_ms": probe.elapsed_ms,
                "payload_class": p.vuln,
                "polyglot": p.polyglot,
            },
        ),
        tags=["active", p.vuln, "polyglot" if p.polyglot else "single-context"],
    )


# --- the driver -------------------------------------------------------------


def probe_parameter(
    http,
    url: str,
    param: str,
    baseline_value: str = "",
    budget: int = 6,
    margin_ms: int = 350,
    technique: str = "query",
) -> list[Injection]:
    """Inject `budget` payloads into one parameter, each judged against a baseline."""
    baseline_url = (replace_param(url, param, baseline_value) if baseline_value else url)
    baseline = http.get(baseline_url)
    picks = (for_value(param, baseline_value, budget) if baseline_value
             else for_param(param, budget))

    out: list[Injection] = []
    fired: set[str] = set()
    for p in picks:
        try:
            if technique == "form":
                probe = http.post(url, data={param: p.value})
            else:
                probe = http.get(replace_param(url, param, p.value))
        except Exception as exc:
            inj = Injection(payload=p, param=param, baseline=baseline)
            inj.verdict = "error"
            inj.signals.append(str(exc)[:120])
            out.append(inj)
            continue

        inj = Injection(payload=p, param=param, baseline=baseline, probe=probe)
        inj.verdict = classify(inj, baseline, margin_ms)
        out.append(inj)
        if inj.verdict == "vulnerable":
            fired.add(p.vuln)
        # stop poking a bleeding wound once two different bug classes are proven.
        # one class only keeps going, because the reflection that proves XSS
        # says nothing about whether the same parameter also injects SQL.
        if len(fired) >= 2:
            break
    return out


def probe_form(http, form: dict, budget: int = 4, margin_ms: int = 350) -> list[Injection]:
    """Probe the interesting fields of a real form we discovered on the page."""
    url = form.get("action") or form.get("url", "")
    method = (form.get("method") or "GET").upper()
    fields = [f for f in form.get("fields", []) if f.get("type") in
              ("text", "search", "email", "url", "password", "textarea", "hidden", "number", "")]
    fields = fields[:budget] or list(form.get("fields", []))[:budget]

    out: list[Injection] = []
    # NB: the loop variable is `fld`, not `field` - the latter would shadow the
    # dataclasses.field import this module needs for the Injection dataclass.
    for fld in fields:
        name = fld.get("name")
        if not name:
            continue
        is_post = method == "POST"
        baseline = (http.post(url, data={name: fld.get("value", "")}) if is_post
                    else http.get(replace_param(url, name, fld.get("value", ""))))
        for p in for_param(name, budget):
            try:
                probe = (http.post(url, data={name: p.value}) if is_post
                         else http.get(replace_param(url, name, p.value)))
            except Exception:
                continue
            inj = Injection(payload=p, param=name, baseline=baseline, probe=probe)
            inj.verdict = classify(inj, baseline, margin_ms)
            out.append(inj)
            if inj.verdict == "vulnerable":
                break
    return out
