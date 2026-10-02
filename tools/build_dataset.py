#!/usr/bin/env python3
"""Build the HF dataset: payloads + demo scan results as JSONL and Parquet.

Runs the bundled demo target so the "sample scan results" are real output from
a real run, not hand-written fiction. Parquet is written by DuckDB when it is
installed; otherwise we emit JSONL only and the script says so loudly, because a
dataset card claiming Parquet that has no Parquet is worse than one that admits
it.

Run:  python tools/build_dataset.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from polyglot_bug_hunter import Hunter, payloads  # noqa: E402
from polyglot_bug_hunter.i18n import SUPPORTED  # noqa: E402
from polyglot_bug_hunter.models import Cvss  # noqa: E402
from polyglot_bug_hunter.safety import is_forbidden_payload  # noqa: E402

OUT = ROOT / "hf_dataset" / "data"

#: The demo target binds a random loopback port, and that port ends up in 42
#: rows of findings.jsonl. Left alone, every build produced a different dataset
#: and a dirty tree, which quietly disabled the dirty-tree guard in
#: tools/release.py. Normalising it here is what makes the build reproducible.
_PORT_RE = re.compile(r"127\.0\.0\.1:\d+")


def normalise(value):
    """Replace the demo's ephemeral loopback port with a stable one."""
    if isinstance(value, str):
        return _PORT_RE.sub("127.0.0.1:8000", value)
    if isinstance(value, list):
        return [normalise(v) for v in value]
    if isinstance(value, dict):
        return {k: normalise(v) for k, v in value.items()}
    return value


def write_jsonl(rows: list[dict], name: str) -> Path:
    path = OUT / name
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(normalise(row), ensure_ascii=False,
                                sort_keys=False) + "\n")
    return path


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------- payloads
    rows = []
    for cls, p in payloads.iter_all():
        av, ac, pr, ui, scope, c, i, a = p.cvss
        cvs = Cvss.build(av=av, ac=ac, pr=pr, ui=ui, scope=scope,
                         conf=c, integ=i, avail=a)
        bad = is_forbidden_payload(p.value)
        rows.append({
            "id": payloads.fingerprint(p),
            "record_type": "payload",
            "vuln_class": p.vuln,
            "bucket": cls,
            "label": p.label,
            "value": p.value,
            "polyglot": p.polyglot,
            "cwe": p.cwe,
            "owasp": p.owasp,
            "note": p.note,
            "confidence": p.confidence,
            "cvss_vector": cvs.vector,
            "cvss_score": cvs.score,
            "severity": cvs.severity.value,
            "destructive": bool(bad),
            "marker": payloads.MARKER,
        })
    p_path = write_jsonl(rows, "payloads.jsonl")
    print(f"payloads.jsonl      {len(rows):4d} rows  {p_path.stat().st_size}B")

    # ------------------------------------------------- demo scan results
    print("running the demo scan (this takes ~8s)...")
    report = Hunter.demo(lang="en", modes=["text", "passive", "image", "audio"])

    # Rewrite the target's ephemeral port to a fixed one *before* anything is
    # derived from it. Finding.fingerprint hashes the endpoint's netloc and the
    # title, and two CSRF findings carry the URL inside the title, so
    # normalising only the endpoint left those two ids moving on every run.
    # Fixing it here also means the ids a reader sees are stable across
    # releases, which is the point of a fingerprint.
    _port = None
    for f in report.findings:
        for attr in ("endpoint", "url", "title", "description", "proof",
                     "remediation", "impact"):
            v = getattr(f, attr, None)
            if isinstance(v, str) and (m := _PORT_RE.search(v)):
                _port = _port or m.group(0)
                setattr(f, attr, _PORT_RE.sub("127.0.0.1:8000", v))
        if f.affected_pages:
            f.affected_pages = [normalise(p) for p in f.affected_pages]
    if _port is not None:
        print(f"  normalised the demo's ephemeral {_port} to 127.0.0.1:8000")

    rows = []
    for f in report.sorted_findings():
        rows.append({
            "id": f.fingerprint,
            "record_type": "finding",
            "title": f.title,
            "severity": f.severity.value,
            "cvss_vector": f.cvss.vector,
            "cvss_score": f.cvss.score,
            "modality": f.modality.value,
            "confidence": f.confidence.value,
            "cwe": f.cwe,
            "owasp": f.owasp,
            "endpoint": f.endpoint,
            "parameter": f.parameter,
            "payload": f.payload,
            "proof": f.evidence.proof[:500],
            "description": f.description[:500],
            "remediation": f.remediation[:500],
            "tags": sorted(set(f.tags)),
            "source": "bundled-demo-target",
        })
    f_path = write_jsonl(rows, "findings.jsonl")
    print(f"findings.jsonl      {len(rows):4d} rows  {f_path.stat().st_size}B")

    # ------------------------------------------------------ scan summary
    # The target's port is whatever the loopback server happened to bind and the
    # duration is wall clock, so both change on every run. Left in, they made
    # every build dirty the tree, which quietly disabled the dirty-tree guard in
    # tools/release.py - you could never publish, because building always
    # produced a diff. A reproducible build is what makes that guard mean
    # anything.
    summary = {
        "record_type": "scan_summary",
        "target": "bundled demo target (localhost)",
        "target_note": ("normalised: the real target carries a random loopback "
                        "port and a wall-clock duration, neither of which is "
                        "reproducible"),
        "modes": report.modes,
        "pages_scanned": len(report.assets),
        "findings": len(report.findings),
        "risk_score": report.risk_score,
        "worst_severity": report.worst.value,
        "counts": report.counts(),
        "by_modality": report.by_modality(),
        "tech": report.tech,
        "detector_version": "1.0.0",
    }
    s_path = write_jsonl([summary], "scans.jsonl")
    print(f"scans.jsonl         {1:4d} rows  {s_path.stat().st_size}B")

    # --------------------------------------------------- bug class index
    stats = payloads.stats()
    index = [{"record_type": "class_index", "vuln_class": k, "count": v}
             for k, v in sorted(stats["per_class"].items())]
    index.append({"record_type": "totals", "total": stats["total"],
                  "polyglot": stats["polyglot"], "classes": stats["classes"],
                  "languages": len(SUPPORTED)})
    i_path = write_jsonl(index, "class_index.jsonl")
    print(f"class_index.jsonl   {len(index):4d} rows  {i_path.stat().st_size}B")

    # --------------------------------------------------------- parquet
    try:
        import duckdb
        con = duckdb.connect()
        for name in ("payloads", "findings", "scans", "class_index"):
            jsonl = OUT / f"{name}.jsonl"
            parquet = OUT / f"{name}.parquet"
            con.execute(
                f"COPY (SELECT * FROM read_json_auto('{jsonl}', "
                f"ignore_errors=true)) TO '{parquet}' (FORMAT PARQUET)")
            print(f"{name+'.parquet':20s} {parquet.stat().st_size}B")
        con.close()
    except Exception as exc:
        print(f"\n! parquet skipped ({type(exc).__name__}: {exc}).")
        print("  install duckdb and re-run:  pip install duckdb")
        print("  JSONL alone still loads fine with:")
        print('    datasets.load_dataset("json", data_dir="data")')

    return 0


if __name__ == "__main__":
    sys.exit(main())
