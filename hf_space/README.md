---
title: PolyglotBugHunter-X
emoji: 🕷️
colorFrom: red
colorTo: purple
sdk: gradio
sdk_version: 4.44.1
app_file: app.py
pinned: true
license: mit
short_description: Multimodal AI web bug hunter — text, image and audio, with CVSS scoring
tags:
  - web-security
  - bug-bounty
  - multimodal
  - agent
  - gradio
  - i18n
  - cvss
  - prompt-injection
  - pentest
---

# 🕷️ PolyglotBugHunter-X

**Bro, imagine an AI that can *see*, *hear*, and *read* a website while hunting bugs
at the same time. Yeah, that's PolyglotBugHunter-X. 🔥**

👉 **[🎨 Try it live right here](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static)** — no install, no account, no API key.

---

## 🚀 One click. Real findings. ~5 seconds.

Press **🚀 Scan Example** and this Space boots a deliberately vulnerable app on
`127.0.0.1`, attacks it with all three modalities, and renders a full report:
SQL injection, IDOR, SSTI, XSS, SSRF, open redirect, weak cookies, exposed
`.env`, RIFF/HTML audio polyglots and a visual prompt-injection canary — each with
a CVSS v3.1 score and evidence you can re-check.

No internet. No third party. No risk of upsetting anyone. It always works, even
on the free CPU tier, because the whole core is stdlib-only.

## 🎛️ Four tabs

| Tab | What you get |
|---|---|
| 🕷️ **Scan** | Crawl + audit any target you're authorized to test. Live progress, downloadable Markdown / HTML / JSON / SARIF. |
| 🎛️ **Multimodal Input** | Build the attack payloads yourself: analyse a text payload against every detector, generate the visual-injection canary and inspect its pixels, synthesise adversarial audio and inspect its container. |
| 📊 **Report** | Severity-sorted findings with proof, affected pages, remediation and inline screenshots. One click each for `.md`, `.html`, `.json`, `.sarif`. |
| 📖 **About** | What the tool does, what's installed in *this* instance, safety model, citation. |

## 🌍 12 languages, auto-detected

🇬🇧 EN · 🇨🇳 中文 · 🇯🇵 日本語 · 🇰🇷 한국어 · 🇮🇩 ID · 🇪🇸 ES · 🇸🇦 AR · 🇷🇺 RU · 🇩🇪 DE · 🇫🇷 FR · 🇵🇹 PT · 🇮🇳 HI

The language is picked from your browser, and the dropdown in the header switches
the entire UI *and* re-renders the report in place. Arabic gets proper RTL
layout. Reports come out localized too.

## 🔍 What it actually checks

**Text** — reflected XSS, SQLi (boolean/error/UNION differentials), command
injection, SSTI, path traversal, SSRF, open redirect, NoSQL/LDAP injection,
prompt injection, IDOR, CSRF, race conditions, DOM-XSS sinks.

**Image** — screenshot diffing (baseline vs payload, hotspot boxes), EXIF/GPS
metadata leaks, alt-text prompt injection, and a generated near-invisible-text
canary.

**Audio** — RIFF/HTML/ZIP polyglots, HTML-in-audio, silent-file acceptance,
decode bombs, spectrogram-injection payloads, tone-encoded instructions,
STT-pipeline prompt injection, voice-auth without challenge-response.

**Passive** — CSP/HSTS/nosniff/X-Frame-Options, cookie flags (HttpOnly,
Secure, SameSite), CORS reflection with credentials, mixed content, TLS
validation, exposed `.env` / `.git` / `wp-config` / `/actuator/env`, stack
fingerprinting, debug leakage, secrets in HTML comments.

Scoring is real **CVSS v3.1** base vectors — cross-checked against RedHat's
`cvss` library over 5000 random vectors, 0 mismatches — plus a saturating
0–100 risk rollup so a score means something in a standup.

## 🛡️ Safety model (read this part)

* Passive by default. **Active probing only happens if you tick the authorization box.**
* Private, loopback, link-local, CGNAT and cloud-metadata ranges are **hard-blocked**
  on this Space. The scanner cannot be used to probe internal networks from here.
* All payloads are non-destructive by construction and are re-checked by
  `safety.is_forbidden_payload()` before leaving the process. No `DROP`, no
  `DELETE`, no `sleep()`, no reverse shells.
* Mandatory rate limiting (5–120 req/min) and a hard request budget.
* Say it out loud: **only test systems you own or have explicit written permission to test.**
  Unauthorised scanning is a crime in most jurisdictions.

## 📦 The rest of the family

* 🧠 [Model repo](https://huggingface.co/Kicaulah/polyglot-bughunter-x) —
  payload vocabulary, detector configuration, scoring profile.
* 🗃️ [Dataset](https://huggingface.co/datasets/Kicaulah/polyglot-bug-patterns) —
  43 payloads across 8 bug classes, plus sample scan results as JSONL + Parquet.
  `load_dataset("Kicaulah/polyglot-bug-patterns")` just works.
* 💻 [GitHub](https://github.com/simonmarc/polyglot-bughunter-x) —
  source, issue tracker, contribution guide.

## 📓 Use it in a notebook

```python
from polyglot_bug_hunter import Hunter

report = Hunter.demo()          # offline demo, no authorization needed
print(report.risk_score, report.counts())
for f in report.sorted_findings()[:5]:
    print(f.severity.value, f.cvss.score, f.title)
```

Full walkthrough: [`data/hf_demo.ipynb`](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static/blob/main/data/hf_demo.ipynb).

## ❓ What it will NOT do

* No GPU needed. The multimodal work here is **file-format and signal analysis**,
  not heavyweight inference — a 2 GB YOLO or Whisper download would time out
  cold starts and cost you visitors.
* No auth-bypass, no credential stuffing, no mass enumeration, no exploit chains.
* No autonomous exploitation. It finds and proves; **you** decide what to do next.
* Static DOM analysis can't prove a sink is exploitable. Findings marked
  `needs-manual-confirm` are honest about that.

## 🤝 Community

Found a bug class we miss, or a payload worth sharing? Every payload is checked
by the same automated safety gate before it lands, so keep it non-destructive.

* 💬 [Open a Discussion](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static/discussions)
* 🔀 [Send a PR with a new payload](https://github.com/simonmarc/polyglot-bughunter-x/pulls)
* 🐛 [Report a detection bug](https://github.com/simonmarc/polyglot-bughunter-x/issues)

## 📝 Changelog

### v1.0.0 — first flight 🚀
* 4-tab Gradio Space, multilingual (12 locales), CPU-only.
* Offline demo target so "Scan Example" always works with zero network.
* 43 detection payloads across 8 classes, 24 of them polyglot.
* CVSS v3.1 scoring validated against an independent implementation.
* Markdown / HTML / JSON / SARIF report rendering, DuckDB-or-sqlite history.
* Localisation for EN, ZH, JA, KO, ID, ES, AR, RU, DE, FR, PT, HI.

<sub>MIT licensed · 🕷️ PolyglotBugHunter-X · authorized use only</sub>