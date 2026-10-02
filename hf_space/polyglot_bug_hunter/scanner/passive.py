"""Passive checks. No payloads, no fuzzing - just read what the server tells us.

This is the part that can run against anything you point at, because nothing
here can change state. It's also where most real-world findings come from,
because missing security headers and sloppy cookies are everywhere.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from ..models import Confidence, Cvss, Evidence, Finding, Modality, Severity
from ..net import Response, detect_tech, meta_content, page_title

# header -> (why it matters, severity, cwe, vector metrics)
SECURITY_HEADERS = {
    "content-security-policy": (
        "No Content-Security-Policy. Nothing stops an injected script from "
        "running with your origin's cookies attached.",
        Severity.MEDIUM, "CWE-693", ("N", "L", "N", "N", "U", "L", "L", "N"),
    ),
    "strict-transport-security": (
        "No HSTS. A user who lands on http:// first is trivially MITM'd for "
        "every subsequent visit.",
        Severity.LOW, "CWE-319", ("N", "L", "N", "N", "U", "L", "L", "N"),
    ),
    "x-content-type-options": (
        "No nosniff. Browsers will MIME-sniff a response you meant to be inert.",
        Severity.LOW, "CWE-16", ("N", "L", "N", "N", "U", "L", "L", "N"),
    ),
    "x-frame-options": (
        "No frame protection. This page can be iframed, which is how clickjacking "
        "and session-riding attacks work.",
        Severity.LOW, "CWE-1021", ("N", "L", "N", "R", "U", "L", "H", "N"),
    ),
    "referrer-policy": (
        "No Referrer-Policy. Full URLs (often with tokens) leak to third parties "
        "in the Referer header.",
        Severity.INFO, "CWE-200", ("N", "L", "N", "N", "U", "L", "L", "N"),
    ),
    "permissions-policy": (
        "No Permissions-Policy. Camera, mic, geolocation stay available to any "
        "iframe you embed.",
        Severity.INFO, "CWE-16", ("N", "L", "N", "N", "U", "L", "L", "N"),
    ),
}

# Files that should never be public. We only *ask* if they exist; we never
# download anything and never escalate beyond a 200/401/403 status check.
EXPOSURE_PROBES = [
    ("/.env", "CWE-538", "critical", "Django/Node env file with secrets"),
    ("/.git/config", "CWE-538", "critical", "source control config, full history"),
    ("/wp-config.php.bak", "CWE-538", "high", "WordPress DB credentials"),
    ("/.DS_Store", "CWE-200", "low", "directory listing hint"),
    ("/backup.zip", "CWE-538", "high", "often full source + creds"),
    ("/phpinfo.php", "CWE-200", "medium", "PHP config dump"),
    ("/server-status", "CWE-200", "medium", "Apache status page"),
    ("/actuator/env", "CWE-200", "critical", "Spring Boot environment + secrets"),
    ("/.well-known/security.txt", "CWE-16", "info", "security contact (good practice)"),
]


@dataclass(slots=True)
class PassiveResult:
    findings: list[Finding]
    tech: list[str]
    title: str
    asset_notes: list[str]


def check_headers(resp: Response, url: str) -> list[Finding]:
    out: list[Finding] = []
    is_https = url.lower().startswith("https://")

    for header, (why, sev, cwe, metrics) in SECURITY_HEADERS.items():
        value = resp.header(header)
        if value:
            continue
        # HSTS only matters on https, Referrer-Policy/XFO too. CSP matters always.
        if header == "strict-transport-security" and not is_https:
            continue
        out.append(
            Finding(
                title=f"Missing security header: {header}",
                severity=sev,
                modality=Modality.PASSIVE,
                cvss=Cvss.build(*metrics),
                owasp="A05:2021 - Security Misconfiguration",
                cwe=cwe,
                url=url,
                endpoint=url,
                confidence=Confidence.HIGH,
                description=why,
                impact="Weakens defence in depth; alone it is rarely exploitable alone.",
                remediation=f"Add `{header}: <value>` at the edge or in your framework config.",
                evidence=Evidence(
                    request=f"HEAD {url}",
                    response_snippet="\n".join(f"{k}: {v}" for k, v in
                                              list(resp.headers.items())[:14]),
                    proof=f"header '{header}' absent from response",
                    extra={"observed_headers": sorted(resp.headers)},
                ),
                tags=["passive", "headers", "hardening"],
                scope="host",
            )
        )

    # CSP present but toothless
    csp = resp.header("content-security-policy")
    if csp:
        weak = [d for d in ("unsafe-inline", "unsafe-eval", "data:", "*",
                            "http://", "https://*") if d in csp.lower()]
        if "unsafe-inline" in weak or "unsafe-eval" in weak or csp.strip() in ("", "*"):
            out.append(
                Finding(
                    title="Content-Security-Policy is present but weak",
                    severity=Severity.LOW,
                    modality=Modality.PASSIVE,
                    cvss=Cvss.build("N", "L", "N", "R", "U", "L", "L", "N"),
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe="CWE-693",
                    url=url,
                    endpoint=url,
                    confidence=Confidence.HIGH,
                    description=f"CSP contains {', '.join(weak)} - inline script still runs.",
                    impact="CSP is not actually blocking XSS payloads.",
                    remediation="Drop unsafe-inline/unsafe-eval; use nonces or hashes.",
                    evidence=Evidence(proof=csp[:300], request=f"GET {url}"),
                    tags=["passive", "csp"], scope="host",
                )
            )
        if "frame-ancestors" not in csp.lower() and not resp.header("x-frame-options"):
            out.append(
                Finding(
                    title="CSP missing frame-ancestors (clickjacking)",
                    severity=Severity.LOW,
                    modality=Modality.PASSIVE,
                    cvss=Cvss.build("N", "L", "N", "R", "U", "L", "H", "N"),
                    cwe="CWE-1021",
                    owasp="A05:2021 - Security Misconfiguration",
                    url=url,
                    endpoint=url,
                    confidence=Confidence.MEDIUM,
                    description="CSP exists but allows being framed by anyone.",
                    impact="Clickjacking / session riding.",
                    remediation="Add `frame-ancestors 'none'` (or your own allowlist).",
                    evidence=Evidence(proof=csp[:300], request=f"GET {url}"),
                    tags=["passive", "clickjacking"], scope="host",
                )
            )
    return out


def check_cookies(resp: Response, url: str) -> list[Finding]:
    """Set-Cookie flag audit. SameSite is the one everybody forgets."""
    raw = ";".join(resp.set_cookie_raw)
    if not raw:
        return []
    out: list[Finding] = []

    if "httponly" not in raw.lower():
        out.append(
            Finding(
                title="Session cookie missing HttpOnly",
                severity=Severity.MEDIUM,
                modality=Modality.PASSIVE,
                cvss=Cvss.build("N", "L", "N", "R", "U", "L", "H", "N"),
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-1004",
                url=url,
                endpoint=url,
                confidence=Confidence.HIGH,
                description="A cookie set here is readable from JavaScript, so any XSS "
                            "on the origin exfiltrates the session immediately.",
                impact="Full session hijack from a single XSS.",
                remediation="Set HttpOnly on every session/auth cookie.",
                evidence=Evidence(proof=raw[:300], request=f"GET {url}"),
                tags=["passive", "cookie", "xss-chain"], scope="host",
            )
        )

    if url.lower().startswith("https://") and "secure" not in raw.lower():
        out.append(
            Finding(
                title="Session cookie missing Secure flag",
                severity=Severity.MEDIUM,
                modality=Modality.PASSIVE,
                cvss=Cvss.build("A", "L", "N", "R", "U", "L", "H", "N"),
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-614",
                url=url,
                endpoint=url,
                confidence=Confidence.HIGH,
                description="Cookie will be sent over plain HTTP, so a network attacker "
                            "reading the wire gets the session.",
                impact="Session theft over an untrusted network.",
                remediation="Add `Secure` to the cookie.",
                evidence=Evidence(proof=raw[:300], request=f"GET {url}"),
                tags=["passive", "cookie"], scope="host",
            )
        )

    if "samesite" not in raw.lower():
        out.append(
            Finding(
                title="Session cookie missing SameSite",
                severity=Severity.LOW,
                modality=Modality.PASSIVE,
                cvss=Cvss.build("N", "L", "N", "R", "U", "L", "H", "N"),
                owasp="A01:2021 - Broken Access Control",
                cwe="CWE-1275",
                url=url,
                endpoint=url,
                confidence=Confidence.MEDIUM,
                description="No SameSite means a cross-site POST carries this cookie, "
                            "which is the whole CSRF story.",
                impact="CSRF attacks become viable.",
                remediation="Set `SameSite=Lax` (or Strict) unless you truly need otherwise.",
                evidence=Evidence(proof=raw[:300], request=f"GET {url}"),
                tags=["passive", "cookie", "csrf"], scope="host",
            )
        )
    return out


def check_cors(resp: Response, url: str, http) -> list[Finding]:
    """Send an Origin header and see if the server reflects it."""
    acao = resp.header("access-control-allow-origin")
    if not acao:
        return []
    out: list[Finding] = []

    probe = "https://pbhx-test.example"
    try:
        r2 = http.get(url, headers={"Origin": probe})
        a2 = r2.header("access-control-allow-origin")
        # the dangerous combination: an attacker-controlled origin reflected back
        # AND credentials allowed. That is a cross-origin read of authenticated data.
        if a2 in ("*", probe) and \
                r2.header("access-control-allow-credentials", "").lower() == "true":
            out.append(
                Finding(
                    title="CORS reflects any origin WITH credentials allowed",
                    severity=Severity.HIGH,
                    modality=Modality.PASSIVE,
                    cvss=Cvss.build("N", "L", "N", "R", "C", "H", "L", "N"),
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe="CWE-942",
                    url=url,
                    endpoint=url,
                    confidence=Confidence.HIGH,
                    description="Access-Control-Allow-Origin echoes our attacker origin and "
                                "Access-Control-Allow-Credentials is true. Any website can "
                                "read authenticated responses from this endpoint.",
                    impact="Cross-origin data theft of every authenticated API call.",
                    remediation="Allowlist exact origins. Never reflect Origin when "
                                "credentials are allowed.",
                    evidence=Evidence(
                        request=f"GET {url}  (Origin: {probe})",
                        response_snippet=f"ACAO: {a2}\nACAC: true",
                        proof="arbitrary origin reflected + credentials allowed",
                    ),
                    tags=["passive", "cors", "critical-class"], scope="host",
                )
            )
    except Exception:
        pass

    if acao == "*" and not out:
        out.append(
            Finding(
                title="Wildcard Access-Control-Allow-Origin",
                severity=Severity.LOW,
                modality=Modality.PASSIVE,
                cvss=Cvss.build("N", "L", "N", "N", "U", "L", "L", "N"),
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-942",
                url=url,
                endpoint=url,
                confidence=Confidence.HIGH,
                description="ACAO: * lets any site read this response.",
                impact="Data exposure on endpoints meant to be private.",
                remediation="Replace * with an explicit origin allowlist.",
                evidence=Evidence(proof="access-control-allow-origin: *", request=f"GET {url}"),
                tags=["passive", "cors"], scope="host",
            )
        )
    return out


def check_mixed_content(resp: Response, url: str) -> list[Finding]:
    """HTTPS page loading HTTP subresources = downgrade channel for scripts."""
    if not url.lower().startswith("https://"):
        return []
    hits = re.findall(r"""(?:src|href)\s*=\s*["'](http://[^"']+)["']""",
                      resp.body, re.I)
    hits = [h for h in hits if not h.startswith("http://localhost")
            and not h.startswith("http://127.0.0.1")]
    if not hits:
        return []
    return [
        Finding(
            title="Mixed content: HTTP subresources on an HTTPS page",
            severity=Severity.MEDIUM,
            modality=Modality.PASSIVE,
            cvss=Cvss.build("N", "L", "N", "R", "U", "L", "L", "N"),
            owasp="A02:2021 - Cryptographic Failures",
            cwe="CWE-319",
            url=url,
            endpoint=url,
            confidence=Confidence.HIGH,
            description=f"{len(hits)} http:// subresource(s) load on an https page. A "
                        "network attacker can swap them.",
            impact="Script/asset tampering, keylogging via a swapped JS file.",
            remediation="Serve every subresource over HTTPS or a protocol-relative/CDN URL.",
            evidence=Evidence(proof="\n".join(hits[:8]), request=f"GET {url}"),
            tags=["passive", "tls", "mixed-content"],
        )
    ]


def check_exposure(http, base: str, budget: int = 6) -> list[Finding]:
    """Ask for well-known sensitive paths. Status code only, no content read."""
    out: list[Finding] = []
    for path, cwe, sev, desc in EXPOSURE_PROBES[:budget]:
        target = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        try:
            r = http.get(target)
        except Exception:
            continue
        if r.status not in (200, 206):
            continue
        # a SPA catch-all returns 200 for everything; a real body beats a 200
        if r.content_type in ("text/html",) and len(r.body) < 512 and path != "/.git/config":
            continue
        out.append(
            Finding(
                title=f"Exposed sensitive path: {path}",
                severity=Severity(sev),
                modality=Modality.PASSIVE,
                cvss=Cvss.build("N", "L", "N", "N", "U", "H", "H", "N"),
                owasp="A01:2021 - Broken Access Control",
                cwe=cwe,
                url=target,
                endpoint=target,
                confidence=Confidence.MEDIUM,
                description=f"{desc} returned HTTP {r.status} without authentication.",
                impact="Credential or source disclosure; often instant full compromise.",
                remediation="Remove the file from the deploy artifact, add deny rules, "
                            "and rotate anything that was inside it.",
                evidence=Evidence(
                    request=f"GET {target}",
                    response_snippet=r.snippet("", 0) or r.body[:200],
                    proof=f"HTTP {r.status} {r.reason}, {len(r.body)} bytes, {r.content_type}",
                ),
                tags=["passive", "exposure"], scope="host",
            )
        )
    return out


def check_tls(url: str, timeout: float = 6.0) -> list[Finding]:
    """Cert sanity. Cheap, local, and people genuinely ship expired certs."""
    if not url.lower().startswith("https://"):
        return []
    host = urlsplit(url).hostname or ""
    if not host:
        return []
    out: list[Finding] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return out
    except ssl.SSLCertVerificationError as exc:
        out.append(
            Finding(
                title="TLS certificate verification failed",
                severity=Severity.HIGH,
                modality=Modality.PASSIVE,
                cvss=Cvss.build("N", "L", "N", "N", "U", "H", "H", "N"),
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-295",
                url=url,
                endpoint=host,
                confidence=Confidence.HIGH,
                description=f"Certificate could not be validated: {exc.verify_message or exc}",
                impact="Active MITM by anyone who can redirect traffic.",
                remediation="Install a valid chain from a trusted CA and serve the "
                            "intermediate certificate too.",
                evidence=Evidence(proof=str(exc)),
                tags=["passive", "tls"], scope="host",
            )
        )
    except Exception:
        return out
    return out


def check_meta_tags(resp: Response, url: str) -> list[Finding]:
    out: list[Finding] = []
    gen = meta_content(resp.body, "generator")
    if gen and any(x in gen.lower() for x in ("wordpress", "drupal", "joomla", "typo3")):
        out.append(
            Finding(
                title=f"CMS version disclosed in meta generator ({gen[:60]})",
                severity=Severity.INFO,
                modality=Modality.PASSIVE,
                cvss=Cvss.build(),
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-200",
                url=url,
                endpoint=url,
                confidence=Confidence.HIGH,
                description="The generator meta tag tells an attacker exactly which "
                            "version to look up CVEs for.",
                impact="Targeted exploit selection.",
                remediation="Strip or blank the generator meta tag.",
                evidence=Evidence(proof=gen[:200], request=f"GET {url}"),
                tags=["passive", "fingerprinting", "recon"], scope="host",
            )
        )
    debug_tokens = ("[debug]", "laravel_session", "traceback", "stack trace",
                    "DEBUG = True", "whoops", "sqlstate", "sql syntax",
                    "error in your sql", "uncaught exception", "django debug")
    for tok in debug_tokens:
        if tok.lower() in resp.body.lower():
            out.append(
                Finding(
                    title="Debug information leaked in response body",
                    severity=Severity.MEDIUM,
                    modality=Modality.PASSIVE,
                    cvss=Cvss.build("N", "L", "N", "N", "U", "L", "H", "N"),
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe="CWE-209",
                    url=url,
                    endpoint=url,
                    confidence=Confidence.HIGH,
                    description=f"Response body contains '{tok}'. Debug mode or a raw "
                                "exception is reachable by anyone.",
                    impact="Leaks paths, library versions, queries, occasionally secrets.",
                    remediation="Disable debug output in production and return generic errors.",
                    evidence=Evidence(
                        proof=tok,
                        response_snippet=resp.snippet(tok) or resp.body[:200],
                        request=f"GET {url}",
                    ),
                    tags=["passive", "info-leak"], scope="host",
                )
            )
            break
    return out


def run(http, base_url: str, resp: Response, deep: bool = False) -> PassiveResult:
    """Everything passive, in one pass. Safe to point at literally anything."""
    findings: list[Finding] = []
    findings += check_headers(resp, base_url)
    findings += check_cookies(resp, base_url)
    findings += check_cors(resp, base_url, http)
    findings += check_mixed_content(resp, base_url)
    findings += check_meta_tags(resp, base_url)
    if deep:
        findings += check_exposure(http, base_url)
        findings += check_tls(base_url)

    tech = detect_tech(resp.body, resp.headers)
    return PassiveResult(
        findings=findings,
        tech=tech,
        title=page_title(resp.body),
        asset_notes=[f"{len(resp.headers)} headers", resp.content_type or "unknown type"],
    )


