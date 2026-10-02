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
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from polyglot_bug_hunter import Hunter, payloads  # noqa: E402
from polyglot_bug_hunter.i18n import SUPPORTED  # noqa: E402
from polyglot_bug_hunter.models import Cvss  # noqa: E402
from polyglot_bug_hunter.safety import is_forbidden_payload  # noqa: E402

OUT = ROOT / "hf_dataset" / "data"


def write_jsonl(rows: list[dict], name: str) -> Path:
    path = OUT / name
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
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
    summary = {
        "record_type": "scan_summary",
        "target": report.target,
        "modes": report.modes,
        "pages_scanned": len(report.assets),
        "findings": len(report.findings),
        "risk_score": report.risk_score,
        "worst_severity": report.worst.value,
        "counts": report.counts(),
        "by_modality": report.by_modality(),
        "tech": report.tech,
        "duration_sec": report.duration,
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
