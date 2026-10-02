"""History. DuckDB when it's there, sqlite3 when it isn't.

Every scan gets stored so you can answer "did this used to be worse?" six months
later. `polyglot.scan` + `polyglot.finding` is a flat star schema, because
DuckDB is brilliant at exactly that and terrible at joins that need a rethink
later.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import ScanReport

DDL = """
CREATE TABLE IF NOT EXISTS scan (
    id            VARCHAR PRIMARY KEY,
    target        VARCHAR,
    started_at    DOUBLE,
    finished_at   DOUBLE,
    duration_sec  DOUBLE,
    risk_score    DOUBLE,
    worst         VARCHAR,
    modes         VARCHAR,
    tech          VARCHAR,
    policy_note   VARCHAR,
    finding_count INTEGER,
    counts_json   VARCHAR,
    full_json     VARCHAR
);
CREATE TABLE IF NOT EXISTS finding (
    fingerprint  VARCHAR,
    scan_id      VARCHAR,
    title        VARCHAR,
    severity     VARCHAR,
    cvss         DOUBLE,
    vector       VARCHAR,
    modality     VARCHAR,
    confidence   VARCHAR,
    cwe          VARCHAR,
    owasp        VARCHAR,
    endpoint     VARCHAR,
    parameter    VARCHAR,
    payload      VARCHAR,
    proof        VARCHAR,
    tags         VARCHAR,
    found_at     DOUBLE
);
CREATE TABLE IF NOT EXISTS modality_stats (
    modality  VARCHAR,
    severity  VARCHAR,
    n         INTEGER
);
"""

PARQUET_GLUE = """
COPY scan FROM '{scan}' (FORMAT PARQUET);
COPY finding FROM '{finding}' (FORMAT PARQUET);
COPY modality_stats FROM '{stats}' (FORMAT PARQUET);
"""


@dataclass(slots=True)
class StoreInfo:
    backend: str
    path: str
    scans: int = 0
    findings: int = 0


class Store:
    """Thin wrapper so callers never care which engine answered."""

    def __init__(self, path: str | Path = "artifacts/pbhx.duckdb") -> None:
        self.path = str(path)
        self.backend = "memory"
        self._con: Any = None
        self._is_duck = False

        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)

        try:
            import duckdb  # type: ignore
            self._con = duckdb.connect(self.path)
            self.backend = "duckdb"
            self._is_duck = True
        except Exception:
            if self.path.endswith(".duckdb"):
                self.path = self.path.replace(".duckdb", ".sqlite3")
            self._con = sqlite3.connect(self.path)
            self.backend = "sqlite3"

        self._apply_ddl()

    def _apply_ddl(self) -> None:
        for stmt in (s.strip() for s in DDL.split(";")):
            if not stmt:
                continue
            try:
                self._con.execute(stmt)
            except Exception:
                pass  # engine-specific DDL tolerance, not worth crashing over

    # -- writes ------------------------------------------------------------

    def save(self, report: ScanReport) -> str:
        scan_id = f"{int(report.started_at * 1000):x}-{abs(hash(report.target)) & 0xffff:04x}"
        counts = report.counts()
        full = report.to_dict()

        if self._is_duck:
            self._con.execute(
                "INSERT OR REPLACE INTO scan VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [scan_id, report.target, report.started_at, report.finished_at,
                 report.duration, report.risk_score, report.worst.value,
                 json.dumps(report.modes), json.dumps(report.tech),
                 report.policy_note, len(report.findings),
                 json.dumps(counts), json.dumps(full)],
            )
            rows = [[
                f.fingerprint, scan_id, f.title, f.severity.value, f.cvss.score,
                f.cvss.vector, f.modality.value, f.confidence.value, f.cwe, f.owasp,
                f.endpoint, f.parameter, f.payload[:500], f.evidence.proof[:1000],
                json.dumps(sorted(set(f.tags))), f.discovered_at,
            ] for f in report.findings]
            if rows:
                self._con.executemany("INSERT INTO finding VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            mods: dict[tuple[str, str], int] = {}
            for f in report.findings:
                mods[(f.modality.value, f.severity.value)] = \
                    mods.get((f.modality.value, f.severity.value), 0) + 1
            if mods:
                self._con.executemany(
                    "INSERT INTO modality_stats VALUES (?,?,?)",
                    [[k[0], k[1], v] for k, v in mods.items()])
        else:
            self._con.execute(
                "INSERT OR REPLACE INTO scan VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, report.target, report.started_at, report.finished_at,
                 report.duration, report.risk_score, report.worst.value,
                 json.dumps(report.modes), json.dumps(report.tech),
                 report.policy_note, len(report.findings),
                 json.dumps(counts), json.dumps(full)))
            self._con.executemany(
                "INSERT INTO finding VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(f.fingerprint, scan_id, f.title, f.severity.value, f.cvss.score,
                  f.cvss.vector, f.modality.value, f.confidence.value, f.cwe, f.owasp,
                  f.endpoint, f.parameter, f.payload[:500], f.evidence.proof[:1000],
                  json.dumps(sorted(set(f.tags))), f.discovered_at)
                 for f in report.findings])
            self._con.executemany(
                "INSERT INTO modality_stats VALUES (?,?,?)",
                [(k[0], k[1], v) for k, v in self._modality_counts(report).items()])
        self._con.commit()
        return scan_id

    @staticmethod
    def _modality_counts(report: ScanReport) -> dict[tuple[str, str], int]:
        out: dict[tuple[str, str], int] = {}
        for f in report.findings:
            k = (f.modality.value, f.severity.value)
            out[k] = out.get(k, 0) + 1
        return out

    # -- reads -------------------------------------------------------------

    def _query(self, sql: str) -> list[tuple]:
        try:
            cur = self._con.execute(sql)
            return list(cur.fetchall())
        except Exception:
            return []

    def history(self, limit: int = 20, target: str | None = None) -> list[dict]:
        where = "WHERE target = '" + target.replace("'", "") + "'" if target else ""
        rows = self._query(
            f"SELECT target, started_at, duration_sec, risk_score, worst, finding_count "
            f"FROM scan {where} ORDER BY started_at DESC LIMIT {int(limit)}")
        return [{"target": r[0], "started_at": r[1], "duration": r[2], "risk": r[3],
                 "worst": r[4], "findings": r[5]} for r in rows]

    def trend(self, target: str, limit: int = 30) -> list[dict]:
        return self.history(limit, target)

    def top_findings(self, limit: int = 10) -> list[dict]:
        rows = self._query(
            f"SELECT title, severity, cvss, COUNT(*) AS n FROM finding "
            f"GROUP BY title, severity, cvss ORDER BY cvss DESC, n DESC LIMIT {int(limit)}")
        return [{"title": r[0], "severity": r[1], "cvss": r[2], "seen": r[3]} for r in rows]

    def modality_breakdown(self) -> list[dict]:
        rows = self._query("SELECT modality, severity, SUM(n) FROM modality_stats "
                           "GROUP BY modality, severity")
        return [{"modality": r[0], "severity": r[1], "n": r[2]} for r in rows]

    def info(self) -> StoreInfo:
        scans = self._query("SELECT COUNT(*) FROM scan")
        finds = self._query("SELECT COUNT(*) FROM finding")
        return StoreInfo(self.backend, self.path,
                         scans[0][0] if scans else 0, finds[0][0] if finds else 0)

    # -- export ------------------------------------------------------------

    def export_parquet(self, out_dir: str | Path = "data") -> dict[str, str]:
        """Only DuckDB can do this properly; sqlite users get JSONL instead."""
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        out: dict[str, str] = {}
        if self._is_duck:
            for table in ("scan", "finding", "modality_stats"):
                path = d / f"{table}.parquet"
                self._con.execute(f"COPY (SELECT * FROM {table}) TO '{path}' (FORMAT PARQUET)")
                out[table] = str(path)
        else:
            for table in ("scan", "finding", "modality_stats"):
                path = d / f"{table}.jsonl"
                with path.open("w", encoding="utf-8") as fh:
                    for row in self._query(f"SELECT * FROM {table}"):
                        fh.write(json.dumps([str(x) if isinstance(x, (bytes, bytearray)) else x
                                             for x in row], default=str) + "\n")
                out[table] = str(path)
        return out

    def load_many(self, reports: Iterable[ScanReport]) -> int:
        n = 0
        for r in reports:
            self.save(r)
            n += 1
        return n

    def close(self) -> None:
        try:
            self._con.close()
        except Exception:
            pass


def schema() -> str:
    return DDL


def now() -> float:
    return time.time()
