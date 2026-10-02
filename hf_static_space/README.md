---
title: PolyglotBugHunter-X
emoji: 🕷️
colorFrom: red
colorTo: purple
sdk: static
app_file: index.html
pinned: true
license: mit
short_description: Multimodal web bug hunter, 100% in your browser
tags:
  - web-security
  - bug-bounty
  - multimodal
  - agent
  - i18n
  - cvss
  - prompt-injection
  - static-space
---

# 🕷️🔥 PolyglotBugHunter-X

![demo](https://kicaulah-polyglot-bughunter-x-static.static.hf.space/demo.gif)

**Bro, imagine an AI that can *see*, *hear*, and *read* a website while hunting bugs
at the same time. Yeah, that's PolyglotBugHunter-X.**

👉 **[🎨 The live demo](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static)**
👉 **[📊 Dataset](https://huggingface.co/datasets/Kicaulah/polyglot-bug-patterns)** ·
**[🧠 Model](https://huggingface.co/Kicaulah/polyglot-bughunter-x)** ·
**[💻 GitHub](https://github.com/skamy64-ux/polyglot-bughunter-x)**

---

## 🚀 One click. Real report. Zero install.

Press **🚀 Scan Example**. It boots a deliberately vulnerable app *inside the tab*,
attacks it across all three modalities, and renders a full report — SQL injection,
IDOR, SSTI, XSS, SSRF, open redirect, CSRF, weak cookies, exposed `.env`, audio
polyglots and a visual prompt-injection canary — each with a **CVSS v3.1** score
and the exact evidence that produced it.

**No server. No account. No API key. No network.** Everything runs in your browser.

## 🎛️ Four tabs

| Tab | What you get |
|---|---|
| 🕷️ **Scan** | Run the full multimodal scan. Live progress, filterable findings, downloadable Markdown / HTML / JSON / SARIF. |
| 🎛️ **Multimodal** | Build the payloads yourself: classify a text payload against every detector, generate the visual-injection canary and inspect its pixels, synthesise adversarial audio and inspect its container. |
| 📊 **Report** | Severity-sorted findings with proof, affected pages, remediation. One click each for `.md`, `.html`, `.json`, `.sarif`. |
| 📖 **About** | What the tool does, what's available in a browser tab vs a server, the safety model, citation. |

## 🌍 12 languages, auto-detected

🇬🇧 EN · 🇨🇳 中文 · 🇯🇵 日本語 · 🇰🇷 한국어 · 🇮🇩 ID · 🇪🇸 ES · 🇸🇦 AR · 🇷🇺 RU ·
🇩🇪 DE · 🇫🇷 FR · 🇵🇹 PT · 🇮🇳 HI

160 keys each, 100% coverage, no blanks. Detected from `navigator.language`; the
dropdown switches the entire UI *and* re-renders the report. Arabic gets proper
RTL. Your choice persists across reloads.

## 🔍 What it checks

**Text** — reflected XSS, SQLi (boolean/error/UNION differentials), command
injection, SSTI, path traversal, SSRF, open redirect, NoSQL/LDAP injection,
prompt injection, IDOR, CSRF, DOM-XSS sinks.

**Image** — pixel diffing with hotspot boxes (baseline vs payload render),
visual prompt-injection canary generation, page-content instruction detection.

**Audio** — RIFF/HTML/ZIP polyglots, HTML-in-audio, silent-file acceptance,
spectrogram injection, tone-encoded instructions, loudness in dBFS, decode bombs.

**Passive** — CSP/HSTS/nosniff/X-Frame-Options, cookie flags, CORS reflection with
credentials, mixed content, exposed `.env`/`.git`/`wp-config`/`/actuator/env`,
debug leakage, secrets in comments.

Scoring is real **CVSS v3.1** base vectors, cross-checked against the Python
original over **5000 random vectors**, plus a saturating 0–100 risk rollup.

## 🧪 This is tested, not asserted

A hand-written port is a liability unless something proves it agrees with the
original. Three harnesses, all runnable:

```bash
python tools/dump_js_reference.py        # dump the Python behaviour to JSON
node tools/test_static_space.mjs         # 312 cross-checks: JS port == Python
node tools/test_static_app.mjs           # 71 app-level checks, headless
python tools/test_static_browser.py      # 57 checks in real Chromium
python -m pytest -q                      # 330 checks on the Python side
```

The browser suite drives the actual page: modules loading over HTTP, tabs
switching, the language dropdown re-rendering a live report, RTL for Arabic, the
scan producing findings, and the canvas canary drawing real invisible glyphs.

## 🛡️ Safety

* A Static Space **has no server**, so it *cannot* send a request to anyone. The
  demo target is a port of the deliberately broken app that ships with the Python
  library, running inside your tab.
* Every payload in the catalogue is **non-destructive** by construction, checked by
  the same gate the scanner uses at runtime. No `DROP`, no `DELETE`, no `sleep()`,
  no reverse shells.
* Paste a destructive payload into the payload lab and it tells you why it was
  refused, instead of pretending it sent it.

> ⚠️ **Authorized use only.** The Python tool sends real HTTP requests. Only point
> it at systems you own or have explicit written permission to test. Unauthorised
> scanning is illegal in most jurisdictions.

## ❓ What this Static Space can't do

* **No real scanning.** There is no server, so no requests to real hosts. Use the
  [Python package](https://github.com/skamy64-ux/polyglot-bughunter-x) for that.
* **No Playwright screenshots** — no browser-to-browser control, so the image
  modality works on rendered canvas rather than real page screenshots.
* **No DuckDB history** — reports download, they don't persist.
* **No faster-whisper STT** — too heavy for a tab, and unnecessary here since the
  audio payloads are synthesised locally anyway.

## 📓 Python quick start

```python
from polyglot_bug_hunter import Hunter

report = Hunter.demo()          # offline demo, no authorization needed
print(report.risk_score, report.counts())
```

## 🤝 Community

Found a bug class we miss, or a payload worth adding? Every payload goes through
the same automated safety gate, so keep it non-destructive.

* 💬 [Discussions](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static/discussions)
* 🔀 [PRs](https://github.com/skamy64-ux/polyglot-bughunter-x/pulls)
* 🐛 [Issues](https://github.com/skamy64-ux/polyglot-bughunter-x/issues)

## 📝 Changelog

### v1.0.0 — first flight 🚀
* Static Space: 4 tabs, 12 locales, RTL, 100% client-side.
* 43 payloads across 8 classes, 24 polyglot.
* JS port of the detector, cross-validated against the Python original on 440
  automated checks.
* Hand-rolled PNG canary on canvas, WAV synthesis by hand, pixel diff with
  hotspot boxes.

<sub>MIT licensed · 🕷️ PolyglotBugHunter-X · authorized security testing only</sub>