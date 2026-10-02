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
task_categories:
  - text-classification
  - tabular-classification
  - other
tags:
  - web-security
  - bug-bounty
  - security
  - payloads
  - polyglot
  - multimodal
  - adversarial
  - prompt-injection
  - cvss
  - owasp
  - cwe
size_categories:
  - n<1K
dataset_info:
  features:
  - name: id
    dtype: string
  - name: record_type
    dtype: string
  - name: vuln_class
    dtype: string
  - name: value
    dtype: string
configs:
- config_name: payloads
  data_files:
  - split: train
    path: data/payloads.jsonl
- config_name: findings
  data_files:
  - split: train
    path: data/findings.jsonl
- config_name: scans
  data_files:
  - split: train
    path: data/scans.jsonl
- config_name: class_index
  data_files:
  - split: train
    path: data/class_index.jsonl
---

![demo](https://kicaulah-polyglot-bughunter-x-static.static.hf.space/demo.gif)

# 🗃️ Polyglot Bug Patterns

**[🐝 Dataset](https://huggingface.co/datasets/Kicaulah/polyglot-bug-patterns)** ·
**[🎨 Space](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static)** ·
**[🧠 Model](https://huggingface.co/Kicaulah/polyglot-bughunter-x)** ·
**[💻 GitHub](https://github.com/skamy64-ux/polyglot-bughunter-x)**

---

Bro, imagine a dataset of **43 non-destructive attack payloads** across **8 bug
classes** — 24 of them *polyglot*, meaning a single string that's simultaneously
plausible HTML, JS, SQL **and** shell, so it escapes whatever context your app
dropped it into. Plus **real detector output** from a full multimodal scan.

Everything here is synthesised or locally generated. No real-world traffic, no
scraped data, no user data.

## 📦 What's inside

| Config | Rows | What it is |
|---|---:|---|
| `payloads` | 43 | Every detection payload: value, bug class, CWE, OWASP, CVSS v3.1 vector+score, polyglot flag, and a `destructive` safety flag. |
| `findings` | 36 | Real findings from one full scan of the bundled demo target, with proof strings, endpoints, remediation, tags. |
| `scans` | 1 | Scan-level rollup: pages scanned, risk score, counts by severity, modality breakdown. |
| `class_index` | 9 | Per-class counts plus totals. |

Each config ships **JSONL and Parquet**, so both of these work:

```python
from datasets import load_dataset

ds = load_dataset("Kicaulah/polyglot-bug-patterns", "payloads")
print(ds["train"][0]["value"])
print(ds["train"].filter(lambda r: r["polyglot"])[0]["value"])

findings = load_dataset("Kicaulah/polyglot-bug-patterns", "findings")
print(len(findings["train"]), "findings from one scan")
```

## 🧬 The payload classes

| Class | n | Examples |
|---|---:|---|
| `sqli` | 8 | `' OR 1=1 -- `, `UNION SELECT NULL`, MySQL error-based double-query, `ORDER BY 99` column-count probe |
| `xss` | 9 | `'"><svg/onload=alert(1)>` attr breakout, `</script><script>` closer, JS-string escape, `{{7*7}}` SSTI |
| `cmdi` | 6 | `;MARKER;`, `$(echo …)`, backticks, `%0a` CRLF, `${IFS}` |
| `traversal` | 5 | `..%2f..%2f..%2fetc%2fpasswd`, `....//....//`, double-double-encoded |
| `ssrf` | 5 | `http://MARKER.oast.invalid/`, `127.0.0.1`, `file:///`, `gopher://`, `[::1]` |
| `prompt-injection` | 4 | "Ignore all previous instructions", `</s>[INST] … [/INST]` chat-template escape, markdown-fence system override |
| `nosql-ldap` | 3 | `*()`, `'; return true; //`, LDAP wildcard filter |
| `redirect` | 3 | absolute, protocol-relative, backslash open redirect |

Every payload carries a unique marker (`PBHX7`) so **reflection is unambiguous** —
that's what makes these usable as training signal for a detector or as a fixture
in your own test suite.

## ⚠️ Safety properties

This is a **defensive** dataset. Concretely:

* Every payload is **non-destructive** by construction. The `destructive` column
  is `false` for all 43 rows — verified by the same `safety.is_forbidden_payload()`
  gate the scanner itself uses at runtime.
* **No** `DROP`/`DELETE`/`UPDATE`/`INSERT`, **no** `system()`/`exec()`/`xp_cmdshell`,
  **no** `sleep()`/`benchmark()`, **no** reverse shells, **no** persistence.
* Time-based blind SQLi is deliberately **absent** — `sleep()` payloads are blocked
  project-wide.
* Payloads are for systems **you own or are authorized to test**. Using them
  against someone else's production box is illegal in most jurisdictions.

## 🧪 Using it

**As a test fixture** — assert your WAF/filter catches the polyglot set:

```python
from datasets import load_dataset
ds = load_dataset("Kicaulah/polyglot-bug-patterns", "payloads")["train"]
for row in ds.filter(lambda r: r["vuln_class"] == "xss"):
    print(row["value"])   # feed each through your own escaping function
```

**As detector training data** — `findings` pairs a payload with the signal that
proved it (`proof`), the CVSS vector, and the remediation. That's a supervised
signal for "was this injection real or a reflection".

**As an LLM security eval** — `prompt-injection` rows are ready-made instruction
overrides for testing whether your model or agent guardrails hold.

## 📊 Provenance

* **payloads** — hand-authored from public documentation (OWASP WSTG, PortSwigger
  cheat sheets, public CVE writeups), rewritten to be non-destructive and
  marker-tagged.
* **findings / scans** — actual output of `Hunter.demo()` against
  `polyglot_bug_hunter.demo_target`, an intentionally vulnerable app that runs on
  localhost inside the test process. Regenerate with
  `python tools/build_dataset.py`.

Nothing was scraped from production systems.

## 📝 Changelog

* **v1.0.0** — initial release: 43 payloads / 8 classes (24 polyglot), 36 findings
  from one full 4-modality demo scan, JSONL + Parquet, 12 languages declared.

## 🤝 Contribute a pattern

Missing a class? Open an issue or PR. The bar: it must be non-destructive
(the automated gate enforces it), documented with a CWE and an OWASP mapping, and
tagged for what detector signal it should produce.

<sub>MIT · 🕷️ PolyglotBugHunter-X · authorized security testing only</sub>