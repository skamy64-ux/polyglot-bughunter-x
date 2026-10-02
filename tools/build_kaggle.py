#!/usr/bin/env python3
"""Assemble a Kaggle-ready dataset folder.

Kaggle is not the Hugging Face Hub: it has no YAML frontmatter, no repo types,
and `kaggle datasets create` wants a flat directory plus a
`dataset-metadata.json`. So this builds `kaggle_dataset/` from the same source
data as `hf_dataset/`, plus a README written for Kaggle's renderer.

```bash
python tools/build_kaggle.py                       # build
kaggle datasets create -u -p kaggle_dataset        # first upload, public
kaggle datasets version -p kaggle_dataset         # later updates
```

Auth comes from `~/.kaggle/access_token` (a single line, chmod 600), or
`~/.kaggle/kaggle.json`, or `KAGGLE_API_TOKEN`. The CLI checks all three, so no
env var is needed once the file exists. Note `-u`: `kaggle datasets create` is
private by default and the `"private": false` in the metadata is ignored.

Kaggle's audience is different from HF's: mostly data scientists doing EDA and
people training models. So this ships the payload catalogue, the findings table
and a runnable notebook, with column descriptions up front rather than buried.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "hf_dataset"
OUT = ROOT / "kaggle_dataset"

#: Kaggle caps public datasets at 100 GB but reviewers prefer small and tidy.
COPY_FILES = [
    "data/payloads.jsonl", "data/payloads.parquet",
    "data/findings.jsonl", "data/findings.parquet",
    "data/scans.jsonl", "data/scans.parquet",
    "data/class_index.jsonl", "data/class_index.parquet",
]

COLUMNS = {
    "payloads": {
        "id": "sha256 fingerprint, first 12 hex chars",
        "record_type": "always 'payload' in this config",
        "vuln_class": "bug class (sqli, xss, cmdi, ssti, traversal, ssrf, redirect, nosql-ldap, prompt-injection)",
        "bucket": "grouping bucket used by the router",
        "label": "short name for the payload",
        "value": "the payload string itself - SENTINEL TAGGED, see the marker column",
        "polyglot": "true if the same string is valid-ish as HTML and JS and SQL and shell",
        "cwe": "Common Weakness Enumeration id",
        "owasp": "OWASP Top 10 (2021) category",
        "note": "what the payload is trying to prove",
        "confidence": "how reliable this payload is as a detector",
        "cvss_vector": "CVSS v3.1 base vector",
        "cvss_score": "CVSS v3.1 base score, 0.0-10.0",
        "severity": "severity band derived from cvss_score",
        "destructive": "always false: every payload passes the project's safety gate",
        "marker": "unique marker (PBHX7) embedded so reflection is unambiguous",
    },
    "findings": {
        "id": "stable fingerprint, identical findings dedupe to one row",
        "record_type": "always 'finding'",
        "title": "one-line description",
        "severity": "critical / high / medium / low / info",
        "cvss_vector": "CVSS v3.1 base vector",
        "cvss_score": "CVSS v3.1 base score",
        "modality": "text / image / audio / passive - which detector produced it",
        "confidence": "high / medium / low",
        "cwe": "CWE id",
        "owasp": "OWASP category",
        "endpoint": "URL where it was found",
        "parameter": "the query parameter or form field",
        "payload": "the exact string that was sent",
        "proof": "the evidence string that made this a finding, not a guess",
        "description": "what the bug is",
        "remediation": "what to do about it",
        "tags": "list of tags",
        "source": "always 'bundled-demo-target' - a deliberately vulnerable app, not a real site",
    },
    "scans": {
        "target": "the demo target",
        "modes": "which modalities ran",
        "pages_scanned": "pages visited",
        "findings": "total findings",
        "risk_score": "0-100 rollup",
        "worst_severity": "highest severity seen",
        "counts": "findings per severity band",
        "by_modality": "findings per modality",
        "tech": "fingerprinted stack",
        "duration_sec": "wall time",
    },
    "class_index": {
        "record_type": "'class_index' rows, plus one 'totals' row",
        "vuln_class": "bug class",
        "count": "payloads in that class",
        "total": "totals row only",
        "polyglot": "totals row only",
        "classes": "totals row only",
        "languages": "totals row only",
    },
}

README = """# 🕷️ Polyglot Bug Patterns — 43 non-destructive web attack payloads + real detector output

**[Live demo](https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static)**
· **[HF version](https://huggingface.co/datasets/Kicaulah/polyglot-bug-patterns)**
· **[GitHub](https://github.com/skamy64-ux/polyglot-bughunter-x)**

---

43 detection payloads across 8 bug classes — **24 of them polyglot**, meaning a
single string that is simultaneously plausible HTML, JS, SQL *and* shell, so it
escapes whatever context the target dropped it into.

Plus **43 real findings** from one full four-modality scan, so you get
`payload → evidence` pairs, not just a list of strings.

Everything is synthesised or locally generated. **No real-world traffic, no
scraped data, no user data.**

## 📦 Files

| File | Rows | Format | What it is |
|---|---:|---|---|
| `payloads.jsonl` / `.parquet` | 43 | JSONL + Parquet | Every payload with class, CWE, OWASP, CVSS v3.1 vector+score, polyglot flag |
| `findings.jsonl` / `.parquet` | 43 | JSONL + Parquet | Real findings from one scan: payload, proof string, remediation, tags |
| `scans.jsonl` / `.parquet` | 1 | JSONL + Parquet | Scan-level rollup: risk score, counts by severity and modality |
| `class_index.jsonl` / `.parquet` | 9 | JSONL + Parquet | Per-class counts plus totals |
| `hf_demo.ipynb` | — | Notebook | Runnable walkthrough, works offline |

## 🧬 Bug classes

| Class | n | Example |
|---|---:|---|
| `sqli` | 8 | `' OR 1=1 -- `, `UNION SELECT NULL`, MySQL error-based double-query |
| `xss` | 9 | `'"><svg/onload=alert(1)>`, `</script><script>`, `{{7*7}}` |
| `cmdi` | 6 | `;MARKER;`, `$(echo …)`, backticks, `%0a` CRLF |
| `traversal` | 5 | `..%2f..%2f..%2fetc%2fpasswd`, `....//....//` |
| `ssrf` | 5 | `http://MARKER.oast.invalid/`, `file:///`, `gopher://`, `[::1]` |
| `prompt-injection` | 4 | "Ignore all previous instructions", `</s>[INST]…[/INST]` |
| `nosql-ldap` | 3 | `*()`, `'; return true; //` |
| `redirect` | 3 | absolute, protocol-relative, backslash open-redirect |

## ⚠️ Safety

This is a **defensive** dataset.

* Every payload is **non-destructive**. The `destructive` column is `false` for
  all 43 rows, verified by the same gate the scanner itself uses at runtime.
* **No** `DROP` / `DELETE` / `UPDATE`, **no** `system()` / `xp_cmdshell`,
  **no** `sleep()` / `benchmark()`, **no** reverse shells, **no** persistence.
* Time-based blind SQLi is deliberately **absent**.
* Only use these against systems you own or have written permission to test.
  Doing otherwise is illegal in most jurisdictions.

## 💡 Using it

```python
import pandas as pd

df = pd.read_parquet("payloads.parquet")
polyglots = df[df.polyglot]
print(f"{len(polyglots)} polyglot payloads across {df.vuln_class.nunique()} classes")

# feed them through your own escaping function and see what leaks
for value in df[df.vuln_class == "xss"].value:
    escaped = my_escape(value)
    assert "<script" not in escaped.lower(), value
```

```python
# supervised signal for a detector: was this injection real or just a reflection?
f = pd.read_parquet("findings.parquet")
print(f.groupby("modality").size())
print(f.groupby(["severity", "cwe"]).size().sort_values(ascending=False).head(10))
```

```python
# LLM / agent security eval
pi = pd.read_parquet("payloads.parquet")
pi = pi[pi.vuln_class == "prompt-injection"]
for value in pi.value:
    send_to_your_model(value)   # does the guardrail hold?
```

## 📊 Column reference

### payloads
{PAYLOAD_COLS}

### findings
{FINDING_COLS}

### scans
{SCAN_COLS}

## 📝 Provenance

* **payloads** — hand-authored from public documentation (OWASP WSTG, PortSwigger
  cheat sheets, public CVE writeups), rewritten to be non-destructive and
  marker-tagged.
* **findings / scans** — actual output of a full scan against a deliberately
  vulnerable app that runs on localhost. Not a real website. Regenerate with
  `python tools/build_dataset.py`.

## 📜 Licence

MIT. Contributions welcome — see
[CONTRIBUTING.md](https://github.com/skamy64-ux/polyglot-bughunter-x/blob/main/CONTRIBUTING.md).
The bar: non-destructive (an automated gate enforces it), documented with a CWE
and OWASP mapping, and tagged for what detector signal it should produce.

<sub>MIT · 🕷️ PolyglotBugHunter-X · authorized security testing only</sub>
"""


def kaggle_username() -> str:
    """Read the owner straight out of the kaggle config.

    Hard-coding it is how a dataset ends up trying to create into somebody
    else's namespace and failing with a 403 that reads like a permissions bug.
    """
    env = os.getenv("KAGGLE_USERNAME")
    if env:
        return env
    for path in (Path.home() / ".kaggle" / "kaggle.json",
                 Path.home() / ".config" / "kaggle" / "kaggle.json"):
        if path.is_file():
            try:
                return json.loads(path.read_text())["username"]
            except Exception:
                pass
    # no config file - the CLI may still know, e.g. when auth came from
    # KAGGLE_API_TOKEN
    import re
    import subprocess
    try:
        out = subprocess.run(["kaggle", "config", "view"], capture_output=True,
                             text=True, timeout=60).stdout
        m = re.search(r"username:\s*(\S+)", out)
        if m and m.group(1) != "None":
            return m.group(1)
    except Exception:
        pass
    return "YOUR_KAGGLE_USERNAME"


def _table(spec: dict[str, str]) -> str:
    rows = ["| Column | Meaning |", "|---|---|"]
    rows += [f"| `{k}` | {v} |" for k, v in spec.items()]
    return "\n".join(rows)


def main() -> int:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    copied = 0
    for rel in COPY_FILES:
        src = SRC / rel
        if not src.is_file():
            print(f"  ! missing {rel} - run: python tools/build_dataset.py")
            continue
        dst = OUT / Path(rel).name
        shutil.copy2(src, dst)
        copied += 1

    nb = ROOT / "notebooks" / "hf_demo.ipynb"
    wheel: Path | None = None
    if nb.is_file():
        # The notebook that ships in the dataset has to work for whoever
        # downloads it, and "pip install polyglot-bug-hunter-x" does not: the
        # project is not on PyPI, so the cell fails outright.
        #
        # The wheel ships as a dataset file rather than being inlined in the
        # notebook. Kaggle's own "Add notebook -> Input -> <dataset>" is the
        # supported way to get a file alongside a notebook, and it keeps the
        # notebook at 17 KB instead of 180 KB of base64.
        import _kaggle_notebook as kn

        wheel = kn.build_wheel(OUT)
        doc = json.loads(nb.read_text(encoding="utf-8"))
        doc = kn.rewrite_install(doc)
        (OUT / "hf_demo.ipynb").write_text(
            json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        copied += 1

    readme = (README
              .replace("{PAYLOAD_COLS}", _table(COLUMNS["payloads"]))
              .replace("{FINDING_COLS}", _table(COLUMNS["findings"]))
              .replace("{SCAN_COLS}", _table(COLUMNS["scans"])))
    (OUT / "README.md").write_text(readme, encoding="utf-8")

    counts = {
        name: sum(1 for _ in (OUT / f"{name}.jsonl").open(encoding="utf-8"))
        for name in ("payloads", "findings", "scans", "class_index")
        if (OUT / f"{name}.jsonl").is_file()
    }
    total = sum(f.stat().st_size for f in OUT.rglob("*") if f.is_file())

    metadata = {
        "title": "Polyglot Bug Patterns",
        "id": f"{kaggle_username()}/polyglot-bug-patterns",
        "licenses": [{"name": "MIT"}],
        # Kaggle validates every keyword against a fixed tag vocabulary and
        # silently drops the rest, so these are the ones it actually accepts for
        # this subject. "cyber security" (two words) is the real slug - the
        # obvious "cybersecurity" is rejected. Kept short on purpose: Kaggle also
        # caps how many *new* categories a single upload may create, and a longer
        # list failed with "exceeded the max category limit".
        "keywords": ["cyber security", "computer science", "programming", "text"],
        # kaggle validates this length before it accepts the upload, so assert it
        # here rather than discovering it as a CLI error
        "subtitle": (
            "43 non-destructive web attack payloads (24 polyglot) plus real "
            "detector output"
        ),
        "description": (
            "A curated catalogue of non-destructive detection payloads for "
            "authorized web security testing, with CVSS v3.1 scoring, CWE and "
            "OWASP mappings, and a companion table of real findings showing which "
            "evidence proves each bug. Ships JSONL and Parquet.\n\n"
            "Every payload is tagged with the marker PBHX7 so reflection is "
            "unambiguous, and every one passes the same non-destructive gate the "
            "scanner applies at runtime. No DROP, no DELETE, no sleep(), no reverse "
            "shells. See the companion Space for the working detector."
        ),
        "resources": [
            {"path": "payloads.parquet", "description": "43 payloads, 16 columns"},
            {"path": "payloads.jsonl", "description": "same, JSON Lines"},
            {"path": "findings.parquet", "description": "43 real findings, 18 columns"},
            {"path": "findings.jsonl", "description": "same, JSON Lines"},
            {"path": "scans.parquet", "description": "scan-level rollup"},
            {"path": "scans.jsonl", "description": "same, JSON Lines"},
            {"path": "class_index.parquet", "description": "per-class counts"},
            {"path": "class_index.jsonl", "description": "same, JSON Lines"},
            {"path": "hf_demo.ipynb", "description": "runnable walkthrough"},
            {"path": wheel.name if wheel else "polyglot_bug_hunter_x-1.0.0-py3-none-any.whl",
             "description": "the scanner as an installable wheel; the notebook "
                            "pip-installs this file"},
        ],
        "data": [
            {"name": "payloads",
             "description": "The payload catalogue. Filter on vuln_class or polyglot."},
            {"name": "findings",
             "description": "Detector output. `proof` explains why each row is a finding."},
            {"name": "scans", "description": "One row describing the scan that produced findings."},
            {"name": "class_index", "description": "Counts per bug class plus totals."},
        ],
        "citation": (
            "@misc{kicauhlah2026, title={PolyglotBugHunter-X: Multimodal AI Web Bug "
            "Hunter}, author={PolyglotBugHunter-X contributors}, year={2026}, "
            "url={https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static} }"
        ),
        "private": False,
    }
    (OUT / "dataset-metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    (OUT / "LICENSE").write_text((ROOT / "LICENSE").read_text(encoding="utf-8"),
                                 encoding="utf-8")

    sub = metadata["subtitle"]
    assert 20 <= len(sub) <= 80, f"kaggle wants a 20-80 char subtitle, got {len(sub)}"
    assert 20 <= len(metadata["title"]) <= 80, f"bad title length {len(metadata['title'])}"
    print(f"owner    : {kaggle_username()}")
    print(f"subtitle : {len(sub)} chars (kaggle wants 20-80)")
    print(f"kaggle dataset assembled: {copied + 3} files, "
          f"{total / 1024:.0f} KB -> {OUT}")
    print(f"  rows: {counts}")
    print()
    print("  upload with:")
    print("    kaggle datasets create -p kaggle_dataset        # first time")
    print("    kaggle datasets version -p kaggle_dataset      # later updates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
