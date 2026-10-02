---
language:
  - en
  - zh
  - ja
  - ko
  - id
  - es
  - ar
  - ru
  - de
  - fr
  - pt
  - hi
license: mit
tags:
  - web-security
  - bug-bounty
  - multimodal
  - agent
  - gradio
  - i18n
  - security
  - cvss
  - prompt-injection
  - penetration-testing
  - xss
  - sqli
pipeline_tag: text-generation
library_name: transformers
inference: false
datasets:
  - Kicaulah/polyglot-bug-patterns
---

# 🕷️ PolyglotBugHunter-X

Bro, imagine an AI that can **see**, **hear**, and **read** a website while hunting
bugs at the same time. Yeah, that's **PolyglotBugHunter-X**. 🔥

👉 **[🎨 Try it live](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static)**** — one click, no install, no server, runs in your browser.

![demo](https://kicaulah-polyglot-bughunter-x-static.static.hf.space/demo.gif) — one click, no install, no server, runs in your browser.
👉 **[📊 Polyglot payload dataset](https://huggingface.co/datasets/Kicaulah/polyglot-bug-patterns)**
👉 **[💻 GitHub](https://github.com/skamy64-ux/polyglot-bughunter-x)**

---

## 🤔 What is this?

A **multimodal agent for automated web security testing**. It reads pages (text),
looks at rendered output (image), and listens to uploads (audio) at the same time,
then reports what it found with **CVSS v3.1** scores and evidence you can re-check.

It ships **43 detection payloads across 8 bug classes** (24 of them *polyglot* —
single strings that are simultaneously plausible HTML, JS, SQL and shell), a
payload-routing engine that guesses the right vector from the parameter name, and
a scoring profile.

This repo holds the artefact side of that: `config.json`, the payload vocabulary,
and the detector/scoring profile that the Space and the library load.

## 🌐 Languages

🇬🇧 EN · 🇨🇳 中文 · 🇯🇵 日本語 · 🇰🇷 한국어 · 🇮🇩 ID · 🇪🇸 ES · 🇸🇦 AR · 🇷🇺 RU ·
🇩🇪 DE · 🇫🇷 FR · 🇵🇹 PT · 🇮🇳 HI

All 12 have a full UI locale (160 keys each) and are declared in the model card
metadata above.

---

## 📁 What's in here

| File | What it is |
|---|---|
| `config.json` | Model/detector config: modality defaults, CVSS profile, safety flags, language list. |
| `payload_vocabulary.json` | All 43 payloads, machine-readable, with class, CWE, OWASP, CVSS vector and a safety classification. |
| `scoring_profile.json` | Severity weights, confidence multipliers and the risk-score curve. |
| `tokenizer_config.json` | Minimal so `transformers` can load the config without complaining. |

```python
import json
from pathlib import Path

cfg = json.loads(Path("config.json").read_text())
print(cfg["modality_defaults"])        # which modalities run when nothing is specified
print(len(json.loads(Path("payload_vocabulary.json").read_text())["payloads"]))

# or, from the Hub, no clone needed:
# from huggingface_hub import hf_hub_download
# hf_hub_download("Kicaulah/polyglot-bughunter-x", "payload_vocabulary.json")
```

---

## 📋 Model Description

* **Architecture:** Not a neural network. This is a **rule-based detection
  profile** plus a **payload vocabulary** — a deterministic agent config.
* **Why not a transformer?** Because a scanner that hallucinates a finding is
  worse than no scanner. Every verdict here comes from a reproducible comparison
  (baseline response vs injected response), and every finding ships the exact
  request, response snippet and signal that produced it.
* **Modality handling:** text (reflective/injection), image (format + metadata +
  pixel diff), audio (container + signal + spectrogram). The "multimodal" part is
  real file-format and signal analysis, not a 7B model in a trench coat.
* **Inputs:** an authorized base URL, crawl budget, and a `ScanPolicy` that
  explicitly states who authorized the test.
* **Outputs:** `ScanReport` — findings with CVSS v3.1 base vectors, severity,
  confidence, OWASP/CWE mapping, evidence, remediation, and a 0–100 risk score.

### Intended Use

* Authorized security testing of web applications you own or have a signed scope
  document for.
* Regression gates in CI (SARIF output plugs into code-scanning UIs).
* Teaching: the bundled demo target makes injection classes reproducible offline.
* Payload research and triage tooling for defenders.

### Out-of-Scope Use

* **Scanning systems you do not own or have written permission to test.** That is
  a crime in most jurisdictions (CFAA 18 U.S.C. §1030, UK CMA 1990 s.1, id. UU
  ITEA Pasal 35-51) and it is also just rude.
* Credential stuffing, brute force, mass enumeration, DoS, or resource exhaustion.
* Exploit chains, privilege escalation, persistence, or lateral movement.
* Any destructive payload. `safety.is_forbidden_payload()` blocks `DROP TABLE`,
  `DELETE FROM`, `system()`, `sleep()`, `rm -rf` and friends at the boundary.
* Bypassing cloud metadata endpoints or using the scanner as an internal port
  scanner. Private/loopback/link-local ranges are refused by default.

---

## 🗂️ Training Data

**None.** This artefact is not trained, so the usual training-data disclosures
don't apply. What it *does* contain is derived from public knowledge:

* **OWASP Top 10 (2021)** and **OWASP Web Security Testing Guide** — bug class
  taxonomy, testing methodology, remediation guidance.
* **CWE** identifiers for each finding class.
* **CVSS v3.1 specification** (FIRST) — the scoring formula, implemented from the
  published weights.
* **Publicly documented payloads** for each injection class, rewritten to be
  non-destructive and marker-tagged (`PBHX7`) so reflection is unambiguous.
* **Zero private, zero scraped, zero user data.** No target traffic, responses or
  screenshots from real scans are included anywhere in this project.

## 📊 Evaluation

| Check | Result |
|---|---|
| CVSS v3.1 base score vs RedHatProductSecurity `cvss` | **0 mismatches / 5000 random vectors** |
| Detection recall on the bundled vulnerable demo (13 injected flaw classes) | **13/13 classes found** |
| False-positive behaviour on the demo's non-vulnerable endpoints | 0 criticals |
| Locale key coverage (12 languages × 160 keys) | **100%, 0 missing** |
| Payload safety gate | 43/43 payloads pass; 17 destructive patterns blocked |
| Runtime, free CPU tier, cold install | gradio only, no GPU, demo scan ~5s |

Per-finding `confidence` is reported alongside severity precisely so you can tell
"proven by a differential" from "static analysis says look here".

## ⚠️ Limitations

* **Static DOM analysis is not proof.** `innerHTML` sinks found by pattern
  matching are flagged `needs-manual-confirm` — confirming them needs a browser
  and a payload you control.
* **No auth.** This tool scans as an anonymous visitor. Authenticated findings
  (IDOR behind a login, horizontal privilege escalation) need a session cookie
  hook that isn't shipped, because shipping credential handling into a public
  Space is a bad idea.
* **Time-based SQLi is out of scope.** `sleep()` payloads are blocked by the
  safety gate, so blind/time-based detection isn't implemented. If you need it,
  do it in an isolated lab with your own tooling.
* **The demo target simulates** database and shell behaviour; it doesn't execute
  SQL or commands. Findings against it prove the *detector*, not the vulnerability.
* **Crawl coverage is bounded** by `max_pages`/`max_depth` and same-origin policy.
* **Race detection is probabilistic.** It's a hint for a human to confirm, tagged
  `low` confidence by design.
* **No WAF evasion.** Getting blocked is reported as `blocked`, never as `clean`.

## ⚖️ Bias & Ethical Considerations

* Web app stacks are not evenly represented. Django/Rails/Laravel patterns get
  specific checks; mainframes and obscure CMSs get less.
* Findings are weighted toward *injectable* bugs because those are what the
  payload vocabulary covers. A clean report means "these probes did not trip",
  not "this site is secure" — the report says so too.
* The tool's risk score is a communication aid, not a compliance verdict. Don't
  gate a release on it.
* This project exists to help defenders find bugs they can fix. Reporting
  responsibly: get authorization in writing, disclose privately, give reasonable
  time to remediate.

## 📄 Citation

```bibtex
@misc{polyglotbughunter2026,
  title={PolyglotBugHunter-X: Multimodal AI Web Bug Hunter},
  author={PolyglotBugHunter-X contributors},
  year={2026},
  url={https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static},
  note={MIT licensed. Authorized security testing only.}
}
```

## 📝 Changelog

* **v1.0.0** — initial release: 43 payloads / 8 classes, 12 locales, CVSS v3.1
  profile, safety gate, demo target, dataset companion.

## 🔗 Ecosystem

* 🎨 [Space](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static)
* 🗃️ [Dataset](https://huggingface.co/datasets/Kicaulah/polyglot-bug-patterns)
* 💻 [GitHub](https://github.com/skamy64-ux/polyglot-bughunter-x)
* 🤝 [Discussions — contribute a payload](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static/discussions)

Drop a ⭐ if this is useful. It genuinely helps the project get seen.

<sub>MIT · 🕷️ PolyglotBugHunter-X · authorized use only</sub>