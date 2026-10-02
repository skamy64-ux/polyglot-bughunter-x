# Changelog

All notable changes to PolyglotBugHunter-X. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Optional YOLOv8 / CLIP adapters for object-detection and image-text similarity
  checks (`vision/` is stubbed; the space is there when someone wants it).
- LangChain planner for crawl-path selection behind a feature flag, so a scan
  never *depends* on an LLM being reachable.
- Authenticated scanning via a session-cookie hook, opt-in and off by default in
  the Space.
- Locale coverage for it, pt-BR, tr, nl.

## [1.0.0] - 2026-10-02

First flight. 🚀

### Added
- **Multimodal agent** with four tabs: Scan, Multimodal Input, Report, About.
- **Offline demo target** (`demo_target.py`): an intentionally vulnerable app
  with 13 planted flaw classes, booted on loopback so "Scan Example" needs no
  network and no third party.
- **43 detection payloads across 8 classes**, 24 of them polyglot (valid-ish as
  HTML *and* JS *and* SQL *and* shell), routed by parameter name.
- **Differential injection analysis** — verdicts come from comparing a captured
  baseline against an injected response, not from noticing a reflection:
  - SQLi: boolean row-count deltas, DB error text, UNION column counts, status flips
  - SSTI: `{{7*7}}` → `49` is the proof
  - cmdi: actual shell output in the body
  - XSS: unescaped reflection, checked against surrounding encoding
- **Image modality**: hand-rolled PNG encoder/decoder (zlib + struct, no Pillow),
  pixel diffing with hotspot boxes, EXIF/GPS privacy audit, alt-text injection
  check, and a generated near-invisible-text canary.
- **Audio modality**: 8 synthesised payloads (RIFF/HTML/ZIP polyglots, silence,
  decode bomb, spectrogram injection, tone-encoded instructions), loudness in
  dBFS, STT-pipeline prompt-injection detection.
- **Passive checks**: CSP/HSTS/nosniff/XFO, cookie flags, CORS reflection with
  credentials, mixed content, TLS validation, exposed sensitive paths, stack
  fingerprinting, debug leakage, secrets in comments.
- **Access control**: IDOR one-step walk with PII-shape comparison, CSRF token
  assessment, TOCTOU race probes.
- **CVSS v3.1 base scoring**, cross-checked against RedHatProductSecurity `cvss`
  over 5000 random vectors — 0 mismatches.
- **Reporting**: Markdown, self-contained HTML (screenshots inlined, RTL-aware),
  JSON, and SARIF 2.1.0.
- **History**: DuckDB with a sqlite3 fallback, same API, Parquet export.
- **i18n**: 12 locales × 160 keys, 100% coverage, `navigator.language`
  auto-detection, RTL for Arabic.
- **5-gate safety model**: authorization, network range (including cloud
  metadata), scheme, payload class, method consent — plus a mandatory rate
  limit and request budget.
- **Artifacts**: HF Space, HF Model repo (`config.json` + payload vocabulary +
  scoring profile), HF Dataset (JSONL + Parquet), and a runnable notebook.
- **325 tests**, all passing.

### Deliberate non-features
- Time-based blind SQLi (blocked on purpose; would make the tool a DoS weapon).
- Authentication / credential handling.
- WAF evasion. Blocked probes report as `blocked`, never as `clean`.
- GPU inference. The multimodal work is format and signal analysis; a 2 GB model
  download would cost every Space visitor a cold start.

### Known issues
- Static DOM-sink detection produces `needs-manual-confirm` findings that need a
  browser to confirm. Expected; they are labelled.
- Race detection is probabilistic and reported at low confidence. Expected.
- The crawler is same-origin by default, so a bug reachable only cross-origin is
  not found. `same_origin_only=False` exists in `ScanConfig` for those cases.

[Unreleased]: https://github.com/simonmarc/polyglot-bughunter-x/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/simonmarc/polyglot-bughunter-x/releases/tag/v1.0.0
