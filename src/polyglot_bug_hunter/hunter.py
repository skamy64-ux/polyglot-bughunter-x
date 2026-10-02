"""The hunter. One class, `scan(url)`, report out.

Flow:

    scan(url)
      -> policy gate (no authorization, no bytes)
      -> crawl (stdlib, same-origin, polite)
      -> for each page:
           passive checks (headers/cookies/cors/tls/exposure)
           DOM audit (inline JS sinks, event handlers, comments)
           form analysis (CSRF tokens, login forms)
           injection probes (differential, budgeted)
           IDOR walk (one step, only for id-shaped params)
      -> optional: image (screenshot diff, visual probes)
      -> optional: audio (format smuggling, STT injection)
      -> optional: race (concurrent duplicate writes)
      -> rollup + CVSS + risk score
      -> report md/html/json/sarif + duckdb row

Everything degrades: no playwright, no duckdb, no faster-whisper, no pillow and
it still produces a real report. That's the difference between a tool and a demo.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from . import htmlx, payloads
from .config import ModalityConfig, ScanConfig
from .i18n import Translator, detect
from .models import (
    Asset,
    Confidence,
    Cvss,
    Evidence,
    Finding,
    Modality,
    ScanReport,
    Severity,
)
from .net import Http, Response, page_title
from .report import render
from .safety import AuthorizationError, ConsentRequired, ScanPolicy
from .scanner import access, audio, image, passive, text
from .scanner import race as race_mod
from .storage.db import Store


def _read_version() -> str:
    """The version, from pyproject when it is reachable.

    This used to be a literal, which meant the number in the package and the
    number on the index could disagree: bumping pyproject alone shipped a 1.0.1
    that reported itself as 1.0.0, and nothing caught it because the test that
    compared them imported an already-installed copy. A tag, the wheel filename
    and the commit message all derive from the same file, so this does too.

    Falls back to the literal when running from a checkout with no pyproject in
    reach, which is what an installed wheel looks like.
    """
    import importlib.metadata
    from pathlib import Path

    try:
        return importlib.metadata.version("polyglot-bug-hunter-x")
    except importlib.metadata.PackageNotFoundError:
        pass

    for parent in Path(__file__).resolve().parents:
        candidate = parent / "pyproject.toml"
        if candidate.is_file():
            import re

            m = re.search(r'^version = "([^"]+)"', candidate.read_text(), re.M)
            if m:
                return m.group(1)
    return "0.0.0+unknown"


__version__ = _read_version()


class Hunter:
    """Multimodal web bug hunter. Passive by default, active on request."""

    def __init__(
        self,
        policy: ScanPolicy | None = None,
        config: ScanConfig | None = None,
        modes: list[str] | ModalityConfig | None = None,
        lang: str = "auto",
        on_progress: Callable[[str], None] | None = None,
        store: Store | None = None,
        navigator_language: str | None = None,
    ) -> None:
        self.policy = policy or ScanPolicy()
        self.cfg = config or ScanConfig()
        self.modes = modes if isinstance(modes, ModalityConfig) else ModalityConfig.parse(modes)
        self.t = Translator(lang if lang != "auto" else detect(navigator_language))
        self.lang = self.t.code
        self.http = Http(self.policy, self.cfg)
        self.store = store
        self._progress = on_progress or (lambda _msg: None)
        self.report = ScanReport(target="", modes=self.modes.enabled())

    # -- progress ----------------------------------------------------------

    def _say(self, msg: str) -> None:
        self._progress(self.t.get(msg) if msg in self.t.base or msg in self.t.en else msg)

    # -- main entry --------------------------------------------------------

    def scan(self, url: str, deep: bool = False,
             screenshots: bool | None = None) -> ScanReport:
        """Scan a target. Raises AuthorizationError if the policy says no."""
        url = self.policy.check_url(url if "//" in url else f"https://{url}")
        rep = ScanReport(target=url, modes=self.modes.enabled(),
                         policy_note=self.policy.header_block().splitlines()[0])

        # the crawl root is what we report, redirects are part of the story
        root = self.http.fetch_following(url)
        rep.target = root.url
        if not root.body and root.error:
            rep.notes.append(f"root fetch failed: {root.error}")
            rep.finished_at = time.time()
            return rep

        self._say("app.scan.crawling")
        pages = self._crawl(root.url, root)
        self._say("app.scan.passive")

        for i, (page_url, resp) in enumerate(pages):
            self._say("app.scan.page")
            asset = Asset(url=page_url, status=resp.status, content_type=resp.content_type,
                          title=page_title(resp.body) or page_title(root.body))
            self._scan_page(asset, resp, deep=deep, index=i)

            if screenshots if screenshots is not None else self.cfg.screenshot:
                shot = self._screenshot(page_url, asset)
                if shot:
                    asset.notes.append(f"screenshot: {shot}")

            rep.assets.append(asset)
            # host-scoped findings (missing CSP, weak cookie, exposed .env) are
            # collected across pages and collapsed at the end, so the report says
            # "8 pages affected" instead of repeating the same row eight times.
            rep.findings.extend(asset.findings)
            rep.tech.extend(tech for tech in passive.detect_tech(resp.body, resp.headers)
                            if tech not in rep.tech)

        # ---- image modality -------------------------------------------
        if self.modes.image:
            self._say("app.scan.image")
            rep.findings.extend(self._scan_images(rep, pages))

        # ---- audio modality -------------------------------------------
        if self.modes.audio:
            self._say("app.scan.audio")
            rep.findings.extend(self._scan_audio(rep))

        # ---- race ------------------------------------------------------
        if self.cfg.check_race:
            self._say("app.scan.race")
            rep.findings.extend(self._scan_race(rep, pages))

        # ---- screenshots as evidence ----------------------------------
        rep.screenshots = {}
        for a in rep.assets:
            for note in a.notes:
                if note.startswith("screenshot: "):
                    rep.screenshots[a.url] = note.split("screenshot: ", 1)[1]

        rep.findings = self._collapse(rep.findings, rep.assets)
        rep.notes.extend(self._meta_notes(rep))
        rep.finished_at = time.time()

        if self.store is not None:
            try:
                self.store.save(rep)
            except Exception as exc:
                rep.notes.append(f"store write failed: {exc}")
        self.report = rep          # so save()/report_text() need no arguments
        return rep

    # -- dedupe -------------------------------------------------------------

    @staticmethod
    def _collapse(findings: list[Finding], assets: list[Asset]) -> list[Finding]:
        """One row per bug. Host-scope findings merge and count their pages."""
        out: list[Finding] = []
        seen: dict[str, Finding] = {}
        for f in findings:
            key = f.fingerprint
            if key in seen:
                existing = seen[key]
                if f.endpoint and f.endpoint not in existing.affected_pages:
                    existing.affected_pages.append(f.endpoint)
                if len(f.evidence.extra) > len(existing.evidence.extra):
                    existing.evidence = f.evidence      # keep the richest proof
                continue
            seen[key] = f
            out.append(f)

        for f in out:
            if f.scope == "host" and f.affected_pages:
                f.evidence.proof = (
                    f"{f.evidence.proof} | affects {len(f.affected_pages)} "
                    f"page(s): {', '.join(p.split('/')[2] + p.split('/')[3] if p.count('/') > 2 else p for p in f.affected_pages[:4])}"
                    + (" ..." if len(f.affected_pages) > 4 else "")
                )
        return out

    # -- crawl -------------------------------------------------------------

    def _crawl(self, root_url: str, root: Response) -> list[tuple[str, Response]]:
        """Breadth-first, same-origin, budgeted. The root response we already
        hold is reused instead of re-fetched (one less request on the target)."""
        seen: set[str] = {root_url}
        out: list[tuple[str, Response]] = [(root_url, root)]
        queue: list[tuple[str, int]] = []

        def expand(url: str, resp: Response, depth: int) -> None:
            parser = htmlx.PageParser(url)
            parser.feed(resp.body or "")
            for link in htmlx.crawlable(parser.links, root_url,
                                        self.cfg.same_origin_only, self.cfg.max_pages):
                if link not in seen:
                    seen.add(link)
                    queue.append((link, depth))

        expand(root_url, root, 1)

        while queue and len(out) < self.cfg.max_pages:
            url, depth = queue.pop(0)
            if depth > self.cfg.max_depth:
                continue
            try:
                resp = self.http.get(url)
            except AuthorizationError:
                raise
            except Exception:
                continue
            out.append((url, resp))
            expand(url, resp, depth + 1)
        return out

    # -- per page ----------------------------------------------------------

    def _scan_page(self, asset: Asset, resp: Response, deep: bool = False,
                   index: int = 0) -> None:
        body = resp.body or ""
        parser = htmlx.PageParser(asset.url)
        parser.feed(body)

        # 1. passive
        if self.modes.passive:
            result = passive.run(self.http, asset.url, resp, deep=deep)
            for f in result.findings:
                asset.add(f)

        # 2. DOM audit: inline JS sinks + event handlers + comment recon
        asset.findings.extend(self._audit_dom(parser, body, asset.url))

        # 3. forms -> CSRF + injection
        if self.modes.text:
            asset.findings.extend(self._scan_forms(parser, body, resp, asset, deep))

        # 4. query params -> injection + IDOR
        if self.modes.text:
            asset.findings.extend(self._scan_params(asset, deep))

        asset.forms = [f.to_dict() for f in parser.forms]
        asset.tech = passive.detect_tech(body, resp.headers)

    def _audit_dom(self, parser: htmlx.PageParser, body: str, url: str) -> list[Finding]:
        out: list[Finding] = []
        for script in parser.inline_js:
            for issue in htmlx.audit_inline_js(script):
                if "location" in issue.sink and not issue.source:
                    continue  # a bare `location = "..."` is navigation, not a bug
                out.append(Finding(
                    title=f"Potential DOM XSS sink: {issue.sink}",
                    severity=Severity.HIGH if issue.severity in ("high", "critical")
                             else Severity.MEDIUM,
                    modality=Modality.PASSIVE,
                    cvss=Cvss.build("N", "L", "N", "R", "U", "L", "H", "N"),
                    owasp="A03:2021 - Injection",
                    cwe="CWE-79",
                    url=url,
                    endpoint=url,
                    confidence=Confidence.LOW,
                    description=(
                        f"Inline script assigns to `{issue.sink}`"
                        + (f" using {issue.source}" if issue.source else "")
                        + " without a recognised sanitiser. Static analysis cannot "
                          "prove this one is exploitable - confirm by navigating to "
                          "the page with a payload in the source."
                    ),
                    impact="If an attacker controls the source, this executes script "
                           "in the page's origin.",
                    remediation="Prefer textContent over innerHTML, sanitise with "
                                "DOMPurify, and never build HTML from location or "
                                "postMessage data.",
                    evidence=Evidence(
                        request=f"GET {url}",
                        proof=issue.snippet,
                        extra={"sink": issue.sink, "source": issue.source},
                    ),
                    tags=["dom-xss", "static-analysis", "needs-manual-confirm"],
                ))
        for issue in htmlx.audit_handlers(parser, body):
            out.append(Finding(
                title=f"Untrusted data in inline event handler ({issue.sink})",
                severity=Severity.MEDIUM,
                modality=Modality.PASSIVE,
                cvss=Cvss.build("N", "L", "N", "R", "U", "L", "H", "N"),
                cwe="CWE-79",
                owasp="A03:2021 - Injection",
                url=url, endpoint=url,
                confidence=Confidence.LOW,
                description=f"Inline handler touches {issue.source or 'a data source'} "
                            f"with no sanitiser.",
                impact="XSS if the source is attacker-influenced.",
                remediation="Move the handler into a module, validate the value, "
                            "and use textContent.",
                evidence=Evidence(proof=issue.snippet,
                                  extra={"source": issue.source}),
                tags=["dom-xss", "inline-handler"],
            ))

        # comments leak intent, hosts and occasionally credentials
        for note in htmlx.audit_comments(parser)[:5]:
            if re_secret(note):
                out.append(Finding(
                    title="Possible credential in HTML comment",
                    severity=Severity.MEDIUM,
                    modality=Modality.PASSIVE,
                    cvss=Cvss.build("N", "L", "N", "N", "U", "L", "H", "N"),
                    cwe="CWE-798", owasp="A05:2021 - Security Misconfiguration",
                    url=url, endpoint=url,
                    confidence=Confidence.MEDIUM,
                    description="An HTML comment contains something that looks like a "
                                "credential or internal endpoint.",
                    impact="Direct credential disclosure from view-source.",
                    remediation="Strip comments in production builds.",
                    evidence=Evidence(proof=note[:300], request=f"GET {url}"),
                    tags=["info-leak", "comments", "secret"], scope="host",
                ))
        return out

    def _scan_forms(self, parser: htmlx.PageParser, body: str, resp: Response,
                    asset: Asset, deep: bool) -> list[Finding]:
        out: list[Finding] = []
        forms = parser.forms[: self.cfg.form_budget]

        for form in forms:
            # CSRF is passive: read the form, don't send anything
            if form.method in ("POST", "PUT", "PATCH"):
                assessment = race_mod.assess_csrf(form.to_dict(), body, resp)
                if f := race_mod.csrf_to_finding(assessment, asset.url):
                    out.append(f)

            # login forms are a fun-house mirror of XSS; we look, we don't submit
            if form.is_login and not deep:
                out.append(Finding(
                    title="Login form present - review for brute-force protection",
                    severity=Severity.INFO,
                    modality=Modality.PASSIVE,
                    cvss=Cvss.build(),
                    cwe="CWE-307", owasp="A07:2021 - Identification and Authentication Failures",
                    url=form.action or asset.url, endpoint=form.action or asset.url,
                    confidence=Confidence.HIGH,
                    description="A password form exists. We deliberately do not attempt "
                                "to log in; verify that rate limiting, lockout and MFA "
                                "are in place.",
                    impact="No rate limit on login means credential stuffing at scale.",
                    remediation="Rate limit per account and per IP, add progressive "
                                "delays and MFA, and alert on failures.",
                    evidence=Evidence(proof=f"form at {form.action or asset.url} "
                                            f"with fields: "
                                            f"{[f.get('name') for f in form.fields]}"),
                    tags=["auth", "recon", "no-probe-attempted"],
                ))
                continue

            # active probing of real forms, only when asked for
            if self.policy.active_probing:
                try:
                    for inj in text.probe_form(self.http, form.to_dict(),
                                               budget=self.cfg.input_budget,
                                               margin_ms=self.cfg.timeout_delta_ms):
                        if f := text.to_finding(inj, inj.baseline or resp, form.action or asset.url):
                            out.append(f)
                except ConsentRequired as exc:
                    # this form needs a method we weren't given consent for.
                    # Skip it, say so, keep scanning - the rest of the site is
                    # still in scope and the operator should see that we stopped.
                    out.append(Finding(
                        title=f"Skipped {form.method} form {form.action or '(self)'} "
                              "- no consent for state-changing requests",
                        severity=Severity.INFO,
                        modality=Modality.PASSIVE,
                        cvss=Cvss.build(),
                        cwe="CWE-703",
                        owasp="A05:2021 - Security Misconfiguration",
                        url=form.action or asset.url,
                        endpoint=form.action or asset.url,
                        confidence=Confidence.HIGH,
                        description=f"Found a {form.method} form but did not submit it: {exc}",
                        impact="Untested attack surface. Enable "
                               "allow_state_changing_methods if you own this endpoint.",
                        remediation="Re-run with allow_state_changing_methods=True on a "
                                    "system you control, or test that form manually.",
                        evidence=Evidence(
                            proof=str(exc)[:200],
                            extra={"form_fields": [f.get("name") for f in form.fields]},
                        ),
                        tags=["not-probed", "needs-consent", "coverage-gap"],
                    ))
                except AuthorizationError:
                    raise
                except Exception:
                    continue
        return out

    def _scan_params(self, asset: Asset, deep: bool) -> list[Finding]:
        out: list[Finding] = []
        params = htmlx.interesting_params(asset.url)
        if not params:
            return out

        for name, value in htmlx.rank_params(params)[:6]:
            # IDOR: one step sideways, before we start injecting
            if access.looks_like_id(name) and value:
                try:
                    res = access.analyze(self.http, asset.url, name, value)
                    if f := access.idor_to_finding(res):
                        out.append(f)
                except AuthorizationError:
                    raise
                except Exception:
                    pass

            if not self.policy.active_probing:
                continue

            try:
                injections = text.probe_parameter(
                    self.http, asset.url, name, value,
                    budget=self.cfg.payload_budget,
                    margin_ms=self.cfg.timeout_delta_ms,
                )
            except AuthorizationError:
                raise
            except Exception:
                continue

            baseline = injections[0].baseline if injections else None
            for inj in injections:
                if not (f := text.to_finding(inj, baseline or Response(url=asset.url),
                                             asset.url)):
                    continue
                out.append(f)
                if inj.payload.vuln == "xss" and self.modes.image:
                    if vf := self._screenshot_diff(asset.url, name, inj.payload.value):
                        out.append(vf)
        return out

    # -- image -------------------------------------------------------------

    def _screenshot(self, url: str, asset: Asset) -> str | None:
        if not self.cfg.screenshot:
            return None
        out = Path(self.cfg.output_dir) / "screenshots"
        name = _slug(url) + ".png"
        try:
            shot = asyncio.run(image.capture_screenshot(
                url, out / name, full_page=self.cfg.screenshot_full_page))
        except Exception:
            shot = None
        if shot and self.cfg.keep_screenshots:
            self.report.screenshots[url] = shot
        return shot

    def _screenshot_diff(self, url: str, param: str, payload_value: str) -> Finding | None:
        """Render baseline vs payload and diff the pixels. Playwright optional."""
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception:
            return None
        sep = "&" if "?" in url else "?"
        out = Path(self.cfg.output_dir) / "screenshots"

        async def shoot() -> tuple[Path, Path] | None:
            base_path = out / f"{_slug(url)}-base.png"
            probe_path = out / f"{_slug(url)}-pbhx.png"
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    args=["--no-sandbox", "--disable-dev-shm-usage"])
                ctx = await browser.new_context(viewport={"width": 1280, "height": 900})
                page = await ctx.new_page()
                await page.goto(url, timeout=25000, wait_until="domcontentloaded")
                await page.screenshot(path=str(base_path), full_page=True)
                await page.goto(f"{url}{sep}{param}={payload_value}", timeout=25000,
                                wait_until="domcontentloaded")
                await page.screenshot(path=str(probe_path), full_page=True)
                await browser.close()
            return base_path, probe_path

        try:
            shot = asyncio.run(shoot())
        except Exception:
            return None
        if not shot:
            return None
        base_path, probe_path = shot

        diff = image.visual_diff(base_path.read_bytes(), probe_path.read_bytes(),
                                out_dir=out)
        return image.diff_to_finding(diff, url, param, str(base_path), str(probe_path))

    def _scan_images(self, rep: ScanReport, pages: list[tuple[str, Response]]) -> list[Finding]:
        """Image surface: EXIF leaks, canary visual-injection probe, alt text."""
        out: list[Finding] = []
        for url, resp in pages[:5]:
            parser = htmlx.PageParser(url)
            parser.feed(resp.body or "")

            # alt text mismatch is a classic multimodal-injection channel
            for img in parser.images[:12]:
                alt = (img.get("alt") or "").strip()
                if alt and len(alt) > 12 and any(
                        phrase in alt.lower() for phrase in
                        ("ignore previous", "system prompt", "you are now", "disregard")):
                    out.append(image.scan_for_injected_instructions(
                        alt, f"alt attribute of {img.get('src', '')[:80]}", url)[0]
                        if image.scan_for_injected_instructions(
                            alt, f"alt attribute of {img.get('src', '')[:80]}", url)
                        else Finding(
                            title="Suspicious instruction-like alt text",
                            severity=Severity.MEDIUM, modality=Modality.IMAGE,
                            cvss=Cvss.build(), cwe="CWE-77", url=url, endpoint=url,
                            confidence=Confidence.LOW,
                            description=f"alt text reads like an instruction: {alt[:120]}",
                            impact="Multimodal prompt injection if an LLM reads the page.",
                            remediation="Never let alt text drive model behaviour.",
                            evidence=Evidence(proof=alt[:300]),
                            tags=["image", "alt-text", "prompt-injection"],
                        ))

            # fetch one image and audit its metadata
            for img in parser.images[:3]:
                src = img.get("src", "")
                if not src.startswith(("http://", "https://")):
                    continue
                try:
                    head = self.http.get(src)
                    if head.ok and head.body and len(head.body) < 3_000_000:
                        info = image.inspect(head.body.encode("utf-8", "replace"), src)
                        out.extend(image.audit_exif(info, url))
                except Exception:
                    continue

        # the canary: prove the concept on any page that accepts an image field
        probe = image.build_visual_probe()
        out.append(Finding(
            title="Visual prompt-injection canary generated (attack surface mapped)",
            severity=Severity.INFO,
            modality=Modality.IMAGE,
            cvss=Cvss.build(),
            cwe="CWE-77", owasp="A03:2021 - Injection",
            url=rep.target, endpoint="(generated locally, nothing was uploaded)",
            confidence=Confidence.HIGH,
            description=(
                f"Built a {probe.width}x{probe.height} PNG containing "
                f"'{probe.instruction}' in {probe.hidden_how}. Upload it wherever your "
                f"app accepts an image that a multimodal model will read, and check "
                f"whether the model obeys the text instead of the user."
            ),
            impact="If it works: agent hijack, data exfiltration through the model's "
                   "tools, guardrail bypass.",
            remediation="Do not feed raw user images into a model that can take "
                        "actions. Pre-process: strip near-invisible text, require "
                        "confirmation on tool calls, log every model decision.",
            evidence=Evidence(
                proof=f"hidden_how={probe.hidden_how}, instruction={probe.instruction}",
                extra={"width": probe.width, "height": probe.height,
                       "png_bytes": len(probe.png),
                       "data_uri": image.probe_as_data_uri(probe.png)[:120] + "..."},
            ),
            tags=["image", "prompt-injection", "canary", "multimodal", "ai-security"],
        ))
        return out

    # -- audio -------------------------------------------------------------

    def _scan_audio(self, rep: ScanReport) -> list[Finding]:
        """Audio surface audit. Local synthesis only; no upload happens."""
        out: list[Finding] = []
        suite = audio.build_test_suite()
        endpoint = next((a.url for a in rep.assets if "upload" in a.url.lower()),
                        rep.target)

        for name, data in suite.items():
            try:
                out.extend(audio.audit(data, endpoint, name))
            except Exception:
                continue

        transcript = audio.transcribe(suite["spectrogram-injection.wav"], model_size="tiny")
        if transcript.error:
            rep.notes.append(f"audio STT skipped: {transcript.error}")

        out.append(Finding(
            title=f"Audio adversarial test suite built ({len(suite)} payloads)",
            severity=Severity.INFO,
            modality=Modality.AUDIO,
            cvss=Cvss.build(),
            cwe="CWE-77", owasp="A03:2021 - Injection",
            url=endpoint, endpoint="(generated locally, nothing was uploaded)",
            confidence=Confidence.HIGH,
            description=(
                f"Synthesised {len(suite)} audio payloads locally with the stdlib `wave` "
                f"module: RIFF/HTML polyglots, HTML-in-audio, ZIP-in-audio, a spectrogram "
                f"attack carrying 'ignore all previous instructions', and a tone-encoded "
                f"prompt. Upload each against your voice endpoint and watch what the STT "
                f"pipeline hands to the model."
            ),
            impact="Voice is an untrusted input channel that most apps forget to validate.",
            remediation="Sniff magic bytes, re-encode server-side, cap duration, treat "
                        "transcripts as untrusted text, and never let audio trigger tools.",
            evidence=Evidence(
                proof=", ".join(f"{k} ({len(v)}B)" for k, v in suite.items()),
                response_snippet=(f"transcript engine: {transcript.engine}\n"
                                  f"transcript error: {transcript.error or 'none'}"),
                extra={"suite": {k: len(v) for k, v in suite.items()}},
            ),
            tags=["audio", "adversarial", "canary", "stt", "ai-security"],
        ))
        return out

    # -- race --------------------------------------------------------------

    def _scan_race(self, rep: ScanReport, pages: list[tuple[str, Response]]) -> list[Finding]:
        out: list[Finding] = []
        for url, resp in pages[:3]:
            parser = htmlx.PageParser(url)
            parser.feed(resp.body or "")
            for form in parser.forms[:2]:
                if form.method not in ("POST", "PUT", "PATCH", "DELETE"):
                    continue
                fields = {f["name"]: (f.get("value") or "1")
                          for f in form.fields if f.get("name")}
                if not fields:
                    continue
                try:
                    result = race_mod.race_probe(self.http, form.action, fields,
                                                threads=self.cfg.race_threads)
                    if f := race_mod.race_to_finding(result, resp, form.action):
                        out.append(f)
                except AuthorizationError:
                    raise
                except Exception:
                    continue
        return out

    # -- reporting ---------------------------------------------------------

    def _meta_notes(self, rep: ScanReport) -> list[str]:
        notes = [
            f"Policy: {self.policy.header_block().splitlines()[1]}",
            f"Requests sent: {self.http.stats()['requests']} "
            f"(avg {self.http.stats()['avg_ms']}ms, budget {self.policy.max_requests})",
            f"Rate limit held: {self.policy.rate_per_minute}/min, "
            f"throttle delay {self.policy.throttle_delay}s",
        ]
        if not self.policy.active_probing:
            notes.append("Active probing OFF: only passive + structural checks ran. "
                         "No payloads were sent.")
        if not self.modes.image:
            notes.append("Image modality OFF (Playwright not needed).")
        if not self.modes.audio:
            notes.append("Audio modality OFF.")
        return notes

    def report_text(self, report: ScanReport | None = None) -> str:
        return render.summarize(report or self.report, self.t)

    def save(self, out_dir: str | None = None, basename: str | None = None,
             report: ScanReport | None = None) -> dict[str, str]:
        rep = report or self.report
        if not rep.findings and not rep.assets:
            # silently emitting an empty report is how you end up sending a
            # manager a "0 findings" email about a scan that never happened
            raise ValueError(
                "nothing to save: call scan() first, or demo_only() which scans "
                "for you. pass report=... explicitly if you built one by hand."
            )
        return render.save(rep, out_dir or self.cfg.output_dir, self.lang,
                           basename=basename)

    # -- demo --------------------------------------------------------------

    @classmethod
    def demo_only(cls, lang: str = "en", modes: list[str] | None = None,
                  on_progress: Callable[[str], None] | None = None,
                  output_dir: str = "artifacts",
                  save_report: bool = True) -> tuple[Hunter, ScanReport]:
        """Boot the bundled vulnerable app, scan it, return (hunter, report).

        Zero internet, zero third parties, zero legal exposure. This is what the
        Space's "Scan Example" button calls.
        """
        from .demo_target import DemoServer

        with DemoServer() as srv:
            hunter = cls(
                # localhost is fine here: we started it, it's ours, it's in-process
                policy=ScanPolicy(authorization_confirmed=True,
                                  authorization_note="bundled offline demo target",
                                  active_probing=True,
                                  allow_private_network=True,
                                  # we wrote the target, so submitting its forms
                                  # breaks nothing
                                  allow_state_changing_methods=True,
                                  rate_per_minute=600,
                                  max_requests=400),
                config=ScanConfig(max_pages=8, max_depth=2, screenshot=False,
                                  output_dir=output_dir, payload_budget=6),
                modes=modes or ["text", "passive", "image", "audio"],
                lang=lang,
                on_progress=on_progress,
            )
            report = hunter.scan(srv.url, deep=True)
            report.target = f"bundled demo target (http://127.0.0.1:{srv.port}/)"
            report.notes.insert(0, "Demo mode: the target was a deliberately vulnerable "
                                   "app we started in-process. No third-party system "
                                   "was contacted.")
            if save_report:
                try:
                    hunter.save(basename="demo-report")
                except Exception as exc:
                    report.notes.append(f"could not write demo report: {exc}")
            return hunter, report

    @classmethod
    def demo(cls, **kwargs: Any) -> ScanReport:
        """Same as `demo_only`, just hands you the report."""
        return cls.demo_only(**kwargs)[1]

    @classmethod
    def demo_target(cls, port: int = 0):
        """The bare server, if you want to poke at it in a browser by hand."""
        from .demo_target import DemoServer
        return DemoServer(port)


# --- small helpers ----------------------------------------------------------

_SECRET_HINT = ("password", "passwd", "secret", "api_key", "apikey", "token",
                "credential", "private_key", "aws_")


def re_secret(note: str) -> bool:
    low = note.lower()
    return any(k in low for k in _SECRET_HINT) and len(note) > 12


def _slug(url: str) -> str:
    keep = "".join(c if c.isalnum() else "-" for c in (url or "x"))[:60]
    return "-".join(filter(None, keep.split("-"))) or "page"


def available_capabilities() -> dict[str, bool]:
    """What this install can actually do. Shown in the Space's About tab."""
    caps = {"playwright": False, "duckdb": False, "pillow": False,
            "tesseract": False, "whisper": False, "requests": False}
    try:
        import playwright  # noqa: F401
        caps["playwright"] = True
    except Exception:
        pass
    try:
        import duckdb  # noqa: F401
        caps["duckdb"] = True
    except Exception:
        pass
    try:
        from PIL import Image  # noqa: F401
        caps["pillow"] = True
    except Exception:
        pass
    try:
        import shutil
        caps["tesseract"] = shutil.which("tesseract") is not None
    except Exception:
        pass
    try:
        import faster_whisper  # noqa: F401
        caps["whisper"] = True
    except Exception:
        pass
    try:
        import requests  # noqa: F401
        caps["requests"] = True
    except Exception:
        pass
    return caps


def version() -> str:
    return __version__


def known_targets() -> list[tuple[str, str, str]]:
    """(label, url, what you'll see). Only hosts built for being tested."""
    return [
        ("httpbin.org", "https://httpbin.org/anything",
         "reflection, header echo, CORS. Publicly operated for testing."),
        ("testfire", "https://demo.testfire.net/",
         "deliberately vulnerable static practice site."),
        ("OWASP Juice Shop", "https://owasp.org/www-project-juice-shop/",
         "docs + local install instructions; the hosted app moves around."),
        ("bundled demo", "demo",
         "our own vulnerable app on 127.0.0.1. Offline, always safe."),
    ]


def iterate_payloads() -> Iterable[tuple[str, Any]]:
    return payloads.iter_all()
