# Changelog

All notable changes to PolyglotBugHunter-X. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-10-02

### Changed
- **The 110 KB base64 wheel is gone from both notebooks.** The kernel dropped
  from 180 KB to 17 KB and the dataset notebook from 180 KB to 17.6 KB. The
  wheel now rides along as a dataset file that Kaggle mounts natively, so a
  kernel with `enable_internet: False` installs it offline. A notebook you can
  read is worth more than a payload you cannot review, and a build artifact
  cannot be silently truncated the way a pasted one can.
- The Gradio Space runs on **Gradio 5 and 6**. Dependabot's bump from `<6` to
  `<7` would have shipped a Space that cannot start: Gradio 6 removed
  `Textbox(show_copy_button=...)` and moved `Blocks(theme=..., css=...)` to
  `launch()`. Nothing caught it because the pin kept the app on 5 and
  `pbhx serve` had never been executed.
- `tools/release.py`: one command for the gate, the build, the publish and an
  anonymous re-read of all six destinations. The dataset build is reproducible,
  so the dirty-tree guard can actually pass.
- `pbhx`, a command line with CI-shaped exit codes (0 clean, 1 findings at or
  above `--fail-on`, 2 refused), plus `run.py` which needs no install at all.
- Published on PyPI. `pip install polyglot-bug-hunter-x` works with no
  extras and no account.

### Fixed
- `Natural Language :: Chinese` is not a trove classifier; PyPI wants
  `Chinese (Simplified)` or `(Traditional)`. The server rejects the whole
  upload for it and the version cannot be reused, so
  `tools/check_classifiers.py` now diffs every classifier against the list
  PyPI serves, and runs in the release gate.
- `__version__` was a literal in `hunter.py` while the tag and wheel filename
  derive from `pyproject.toml`, so a version bump could ship a package that
  reported itself as the previous release. One source of truth now.
- `tools/publish.py` printed "uploaded" after the upload had already raised:
  `space_sdk` belongs to `create_repo`, not `upload_folder`, so every Space push
  failed silently while the success line still appeared.
- GitHub references pointed at the Kaggle account. Three accounts on three
  services, one string standing in for two of them.
- The v1.0.0 tag went missing while `CHANGELOG.md` still referenced it.
- The link checker used `HEAD` with a bot User-Agent, so Kaggle — which
  implements neither — reported two live URLs as dead. It also counted a 5xx as
  a verdict on the link rather than a verdict about the host.
- Two tests passed only in the state their author works in, by reading a build
  folder before checking it exists. CI never has that folder.

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

[Unreleased]: https://github.com/skamy64-ux/polyglot-bughunter-x/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/skamy64-ux/polyglot-bughunter-x/releases/tag/v1.0.1
[1.0.0]: https://github.com/skamy64-ux/polyglot-bughunter-x/releases/tag/v1.0.0
