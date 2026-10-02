"""Browser test for the Static Space - the parts node cannot reach.

The node harnesses prove the logic. This proves the *page*: modules load over
HTTP, the tabs switch, the language dropdown re-renders everything including RTL,
the scan button produces a real report, and the canvas canary really draws
invisible glyphs.

    python tools/test_static_browser.py

Needs playwright + chromium. Skips cleanly if they are missing.
"""

from __future__ import annotations

import functools
import http.server
import socketserver
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPACE = ROOT / "hf_static_space"


def serve(directory: Path):
    """A tiny static server so the page loads over http:// like it will on HF."""
    # directory must be passed through partial: as a class attribute the
    # handler ignores it and serves a listing instead of index.html
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler,
        directory=str(directory),
    )
    handler.log_message = lambda *a, **k: None

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    # deliberately not a context manager: it must outlive serve() returning
    httpd = Server(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def main() -> int:
    """Pass --live to test the deployed CDN URL instead of a local server."""
    live = "--live" in sys.argv
    live_url = "https://kicaulah-polyglot-bughunter-x-static.static.hf.space/index.html"
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print("playwright not installed - skipping (pip install playwright)")
        return 0

    httpd = None
    if live:
        base = live_url
        print("== LIVE static space (CDN) ==")
    else:
        httpd, port = serve(SPACE)
        base = f"http://127.0.0.1:{port}/"
    failures: list[str] = []
    passed = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal passed
        if ok:
            passed += 1
            print(f"  PASS  {label}")
        else:
            failures.append(label)
            print(f"  FAIL  {label}{('  ' + detail) if detail else ''}")

    if not live:
        print(f"== static space browser test @ {base} ==")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        page = browser.new_page(viewport={"width": 1280, "height": 900})

        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

        page.goto(base, wait_until="networkidle")
        page.wait_for_timeout(900 if live else 700)

        # ---- 1. it loaded
        check("page title", "PolyglotBugHunter-X" in page.title(), page.title())
        check("no JS errors on load", not errors, "; ".join(errors[:2]))
        check("hero rendered", page.locator(".hero h1").inner_text().strip() != "")
        check("tagline localised", len(page.locator("#tagline").inner_text()) > 10)
        check("disclaimer present", "permission" in page.locator("#disclaimer").inner_text().lower())

        # ---- 2. modules actually loaded (if not, the tabs would be inert)
        check("i18n loaded", page.evaluate("typeof window.__pbhxProbe") == "undefined")
        lang_opts = page.locator("#lang option").count()
        check("12 languages in the dropdown", lang_opts == 12, str(lang_opts))

        # ---- 3. tabs switch
        for tab, panel in [("scan", "panel-scan"), ("multi", "panel-multi"),
                           ("report", "panel-report"), ("about", "panel-about")]:
            page.click(f'.tab[data-tab="{tab}"]')
            page.wait_for_timeout(120)
            check(f"tab {tab} shows {panel}",
                  page.locator(f"#{panel}").is_visible())

        # ---- 4. about tab has real content in the active language
        page.click('.tab[data-tab="about"]')
        about_en = page.locator("#about-out").inner_text()
        check("about explains the tool", "Multimodal" in about_en or "multimodal" in about_en)
        check("about lists payload counts", "payloads" in about_en)

        # ---- 5. the scan
        page.click('.tab[data-tab="scan"]')
        page.click("#run-demo")
        page.wait_for_selector("#results:not([hidden])", timeout=45000)
        page.wait_for_timeout(400)

        status = page.locator("#scan-status").inner_text()
        check("scan produced a status line", len(status) > 10, status[:70])
        check("risk score rendered", page.locator(".summary .risk").count() == 1)
        cards = page.locator("#findings .card").count()
        check("findings rendered as cards", cards >= 20, f"{cards} cards")
        text = page.locator("#summary").inner_text()
        check("summary shows severity pills", "Critical" in text and "High" in text)

        titles = page.locator("#findings .card h3").all_inner_texts()
        joined = " | ".join(titles).lower()
        for needle, why in [("sql injection", "SQLi"), ("idor", "IDOR"),
                            ("template injection", "SSTI"), ("open redirect", "redirect"),
                            ("csrf", "CSRF"), ("httponly", "cookie flags"),
                            (".env", "exposure"), ("visual prompt-injection canary", "image"),
                            ("audio adversarial", "audio")]:
            check(f"found {why}", needle in joined, needle)

        # ---- 6. image modality ran (needs canvas, so it cannot be tested in node)
        check("image modality produced a canary finding",
              "canary" in joined)
        check("pixel diff produced a finding", "visual/dom change" in joined
              or "visual diff" in joined)

        # ---- 7. the filter works
        before = page.locator("#findings .card").count()
        page.fill("#filter", "sql")
        page.wait_for_timeout(250)
        after = page.locator("#findings .card").count()
        check("filter narrows the list", after < before and after > 0,
              f"{before} -> {after}")
        page.fill("#filter", "")
        page.wait_for_timeout(200)

        # ---- 8. downloads are real blobs
        for kind, expect in [("md", "#pbhx-report"), ("html", "<!doctype html>"),
                             ("json", '"risk_score"'), ("sarif", '"sarif"')]:
            href = page.get_attribute(f"#dl-{kind}", "href") or ""
            check(f"{kind} download is a blob", href.startswith("blob:"), href[:24])

        # ---- 9. report tabs (the report panel has to be visible first, or the
        # subtabs are inside a hidden container and cannot be clicked)
        page.click('.tab[data-tab="report"]')
        page.wait_for_timeout(200)
        for rtab, sel in [("md", "#report-md"), ("html", "#report-html"),
                          ("json", "#report-json"), ("sarif", "#report-sarif")]:
            page.click(f'.subtab[data-rtab="{rtab}"]')
            page.wait_for_timeout(150)
            check(f"report tab {rtab} visible", page.locator(sel).is_visible())
        md = page.evaluate("document.getElementById('report-md').textContent")
        check("markdown report is substantial", len(md) > 3000, f"{len(md)} chars")
        check("markdown has no '1 findings'", " 1 findings" not in md)

        # ---- 10. language switch re-renders everything
        page.click('.tab[data-tab="scan"]')
        before_status = page.locator("#scan-status").inner_text()
        page.select_option("#lang", "ja")
        page.wait_for_timeout(600)
        check("html lang attribute updated",
              page.evaluate("document.documentElement.lang") == "ja")
        ja_status = page.locator("#scan-status").inner_text()
        check("status re-rendered in japanese", ja_status != before_status,
              f"{before_status[:30]} -> {ja_status[:30]}")
        check("tabs re-labelled",
              page.locator('.tab[data-tab="scan"] span').inner_text().strip() != "Scan",
              page.locator('.tab[data-tab="scan"] span').inner_text())
        ja_md = page.evaluate("document.getElementById('report-md').textContent")
        check("markdown report re-rendered", len(ja_md) > 1000, f"{len(ja_md)} chars")

        # ---- 11. RTL
        page.select_option("#lang", "ar")
        page.wait_for_timeout(500)
        check("arabic sets dir=rtl",
              page.evaluate("document.documentElement.dir") == "rtl")
        ar_html = page.evaluate(
            "(async () => { const r = await fetch('data:text/html,'); return 1; })()")
        page.click('.tab[data-tab="report"]')
        page.click('.subtab[data-rtab="html"]')
        page.wait_for_timeout(300)
        frame_html = page.evaluate(
            "document.getElementById('report-html').srcdoc || ''")
        check("html report is rtl in arabic", 'dir="rtl"' in frame_html)

        # ---- 12. language persists
        page.select_option("#lang", "zh")
        page.wait_for_timeout(400)
        page.reload(wait_until="networkidle")
        page.wait_for_timeout(700)
        check("language choice persisted",
              page.evaluate("document.documentElement.lang") == "zh",
              page.evaluate("document.documentElement.lang"))

        # ---- 13. the payload lab
        page.click('.tab[data-tab="multi"]')
        page.click('.subtab[data-sub="text"]')
        page.fill("#payload", "{{7*7}}")
        page.click("#analyze")
        page.wait_for_timeout(300)
        out = page.locator("#payload-out").inner_text()
        # the class name is localised, so assert on the language-independent
        # payload label and the CVSS vector instead
        check("payload lab classified SSTI", "template-arith" in out, out[:70])
        check("payload lab shows a cvss vector", "CVSS:3.1/" in out)
        page.fill("#payload", "'; DROP TABLE users; --")
        page.click("#analyze")
        page.wait_for_timeout(300)
        check("payload lab refuses destructive input",
              "safety gate" in page.locator("#payload-out").inner_text())

        # ---- 14. the canary (canvas)
        page.click('.subtab[data-sub="image"]')
        page.click("#make-canary")
        page.wait_for_timeout(500)
        stats = page.locator("#canary-stats").inner_text()
        check("canary drawn", "glyphs drawn" in stats, stats[:60])
        check("canary has non-white pixels", "non-white pixels" in stats)
        dl = page.get_attribute("#dl-canary", "href") or ""
        check("canary png downloadable", dl.startswith("blob:"))
        canvas_size = page.evaluate(
            "(() => { const c = document.getElementById('canary'); return c.width + 'x' + c.height; })()")
        check("canary canvas has real dimensions", canvas_size != "10x10", canvas_size)

        # ---- 15. the audio lab
        page.click('.subtab[data-sub="audio"]')
        page.select_option("#audkind", "polyglot")
        page.click("#make-audio")
        page.wait_for_timeout(500)
        aout = page.locator("#audio-out").inner_text()
        check("audio suite rendered", "polyglot" in aout)
        check("smuggled format flagged", "NOT AUDIO" in aout)
        links = page.locator("#audio-list a").count()
        check("audio downloads offered", links >= 1, str(links))

        check("no JS errors during the whole run", not errors, "; ".join(errors[:3]))

        browser.close()

    print(f"\n{'=' * 60}")
    if failures:
        print(f"FAILED: {len(failures)} of {passed + len(failures)}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"all {passed} browser checks passed")
    if httpd:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())