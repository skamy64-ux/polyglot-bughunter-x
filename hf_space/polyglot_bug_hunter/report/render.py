"""Turn findings into something a human can actually forward to a manager.

Three formats:
  * Markdown - paste into a GitHub issue or an email.
  * HTML     - one self-contained file, screenshots inlined, opens offline.
  * JSON     - stable schema for the dataset and for CI gates.
"""

from __future__ import annotations

import base64
import html as htmllib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from ..i18n import RTL, Translator
from ..models import Finding, ScanReport

SEV_ICON = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}
SEV_COLOR = {
    "critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207",
    "low": "#1d4ed8", "info": "#4b5563",
}
MODALITY_ICON = {"text": "⌨️", "image": "🖼️", "audio": "🎙️", "passive": "👁️"}


def plural(n: int, singular: str, many: str | None = None) -> str:
    """English pluralisation. '1 findings' in a report looks unpolished, and
    people do notice that first."""
    return f"{n} {singular if n == 1 else (many or singular + 's')}"


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _b64_image(path: str) -> str:
    try:
        data = Path(path).read_bytes()
    except Exception:
        return ""
    if len(data) > 4_000_000:
        return ""
    ext = Path(path).suffix.lower().lstrip(".") or "png"
    return f"data:image/{'jpeg' if ext in ('jpg', 'jpeg') else ext};base64,{base64.b64encode(data).decode()}"


# --- markdown ---------------------------------------------------------------


def to_markdown(report: ScanReport, t: Translator | None = None,
                screenshots: dict[str, str] | None = None) -> str:
    t = t or Translator("en")
    shots = screenshots if screenshots is not None else report.screenshots
    counts = report.counts()
    lines: list[str] = []

    lines.append(f"# 🕷️ PolyglotBugHunter-X report — `{report.target}`")
    lines.append("")
    lines.append(f"**{t.get('report.worst')}: {SEV_ICON[report.worst.value]} "
                 f"{t.severity(report.worst.value).upper()}** · "
                 f"risk **{report.risk_score}/100** · "
                 f"{plural(len(report.findings), 'finding')} · "
                 f"{report.duration}s · {', '.join(report.modes)}")
    lines.append("")
    lines.append(f"> 🧨 {t.get('report.disclaimer')}")
    lines.append("")

    # summary table
    lines.append("| " + " | ".join(
        f"{t.severity(s)} ({counts.get(s, 0)})"
        for s in ("critical", "high", "medium", "low", "info")) + " |")
    lines.append("| " + " | ".join("---:" for _ in range(5)) + " |")
    lines.append("| " + " | ".join(
        f"**{counts.get(s, 0)}**" for s in
        ("critical", "high", "medium", "low", "info")) + " |")
    lines.append("|---:|---:|---:|---:|---:|")
    lines.append("")

    if report.tech:
        lines.append(f"**Stack:** {', '.join(report.tech)}  ")
    if report.policy_note:
        lines.append(f"**Scope/authorization:** `{report.policy_note}`  ")
    if not report.tech:
        lines.append("*Stack: not fingerprinted from headers or markup.*  ")
    lines.append(f"**Scanned:** {_ts(report.started_at)}  ")
    lines.append(f"**Modes:** {', '.join(report.modes)}")
    lines.append("")

    # per modality
    by_mod = report.by_modality()
    if len(by_mod) > 1:
        lines.append("## 🧪 Modality coverage")
        lines.append("")
        for mod, n in sorted(by_mod.items(), key=lambda kv: -kv[1]):
            lines.append(f"- {MODALITY_ICON.get(mod, '•')} **{mod}** — "
                         f"{plural(n, 'finding')}")
        lines.append("")

    if not report.findings:
        lines.append(f"## ✅ {t.get('report.clean')}")
        lines.append("")
        lines.append("No injection or misconfiguration signal was detected within the "
                     "configured budget. That is not proof of safety — it means the "
                     "specific probes sent did not trip. Keep an eye on the notes below.")
        lines.append("")
    else:
        for i, f in enumerate(report.sorted_findings(), 1):
            lines.append(_finding_md(f, i, shots, t))
            lines.append("")

    # notes + assets
    if report.notes:
        lines.append("## 📝 Notes")
        lines.append("")
        lines += [f"- {n}" for n in report.notes]
        lines.append("")

    if shots:
        lines.append("## 📸 Screenshots")
        lines.append("")
        for name, path in shots.items():
            lines.append(f"**{name}**")
            lines.append("")
            lines.append(f"![{name}]({path})")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"<sub>PolyglotBugHunter-X · schema {report.schema_version} · "
                 f"{_ts(report.finished_at or time.time())} · "
                 f"MIT licensed · report responsibly</sub>")
    return "\n".join(lines)


def _finding_md(f: Finding, n: int, shots: dict[str, str], t: Translator) -> str:
    icon = SEV_ICON.get(f.severity.value, "•")
    out = [
        f"### {icon} {n}. {f.title}",
        "",
        f"`{f.cvss.score}` **{t.severity(f.severity.value).upper()}** · "
        f"{MODALITY_ICON.get(f.modality.value, '•')} {f.modality.value} · "
        f"confidence `{f.confidence.value}`"
        + (f" · {f.cwe}" if f.cwe else "")
        + (f" · {f.owasp}" if f.owasp else "")
        + (f" · CVSS `{f.cvss.vector}`" if f.cvss.vector else ""),
        "",
    ]
    if f.description:
        out += [f.description, ""]
    if f.impact:
        out += [f"**Impact:** {f.impact}", ""]
    if f.payload:
        out += ["**Payload used**", "", "```", f.payload, "```", ""]
    ev = f.evidence
    if not ev.is_empty():
        out.append("**Evidence**")
        out.append("")
        if ev.request:
            out += ["```http", ev.request, "```", ""]
        if ev.response_snippet:
            out += ["```", ev.response_snippet[:600], "```", ""]
        if ev.proof:
            out += [f"**Proof:** {ev.proof}", ""]
        shot = ev.screenshot or shots.get(f.fingerprint, "")
        if shot:
            out += [f"![evidence]({shot})", ""]
    if f.endpoint or f.parameter:
        out += [f"**Where:** `{f.endpoint or f.url}`"
                + (f" · parameter `{f.parameter}`" if f.parameter else ""), ""]
    if f.remediation:
        out += ["**Fix**", "", f"1. {f.remediation}"]
        if f.description:
            out.append("2. Add a regression test that replays this exact payload.")
        out.append("")
    if f.tags:
        out += ["`" + "` `".join(sorted(set(f.tags))) + "`", ""]
    return "\n".join(out)


# --- html -------------------------------------------------------------------


def to_html(report: ScanReport, t: Translator | None = None,
            screenshots: dict[str, str] | None = None) -> str:
    """Single file, no external assets, RTL-aware, screenshots inlined."""
    t = t or Translator("en")
    shots = screenshots if screenshots is not None else report.screenshots
    esc = htmllib.escape
    dir_attr = "rtl" if t.code in RTL else "ltr"
    counts = report.counts()

    sev_bars = "".join(
        f'<span class="pill" style="background:{SEV_COLOR[s]}">{SEV_ICON[s]} '
        f'{esc(t.severity(s))} {counts.get(s, 0)}</span>'
        for s in ("critical", "high", "medium", "low", "info")
    )

    cards: list[str] = []
    for i, f in enumerate(report.sorted_findings(), 1):
        ev = f.evidence
        img = ""
        shot = ev.screenshot or shots.get(f.fingerprint, "")
        if shot:
            uri = _b64_image(shot)
            img = (f'<img class="shot" alt="screenshot evidence" src="{uri}">'
                   if uri else f'<div class="shot-missing">screenshot: {esc(shot)}</div>')

        # Built out here rather than inline in the template below: a backslash
        # escape inside an f-string *expression* is Python 3.12+ only, and this
        # project supports 3.11.
        req_block = (f'<pre class="req"><b>request</b>\n{esc(ev.request[:900])}</pre>'
                     if ev.request else "")
        resp_block = (f'<pre class="resp"><b>response</b>\n'
                      f'{esc(ev.response_snippet[:900])}</pre>'
                      if ev.response_snippet else "")
        proof_block = (f'<p class="proof"><b>proof:</b> {esc(ev.proof)}</p>'
                       if ev.proof else "")
        impact_block = (f'<p class="impact"><b>Impact:</b> {esc(f.impact)}</p>'
                        if f.impact else "")
        payload_block = (f'<pre class="payload">{esc(f.payload)}</pre>'
                         if f.payload else "")
        tags_block = "".join(f'<span class="tag">{esc(tag)}</span>'
                             for tag in sorted(set(f.tags)))
        cards.append(f"""
<article class="card" style="border-left-color:{SEV_COLOR[f.severity.value]}">
  <h3>{SEV_ICON.get(f.severity.value, '•')} {i}. {esc(f.title)}</h3>
  <div class="meta">
    <span class="score" style="background:{SEV_COLOR[f.severity.value]}">{f.cvss.score}</span>
    <span>{MODALITY_ICON.get(f.modality.value, '•')} {esc(f.modality.value)}</span>
    <span>conf: {esc(f.confidence.value)}</span>
    {f'<span>{esc(f.cwe)}</span>' if f.cwe else ''}
    {f'<span>{esc(f.owasp)}</span>' if f.owasp else ''}
    <code>{esc(f.cvss.vector)}</code>
  </div>
  <p>{esc(f.description)}</p>
  {impact_block}
  {payload_block}
  {req_block}
  {resp_block}
  {proof_block}
  {img}
  <p class="where"><code>{esc(f.endpoint or f.url)}</code>
     {f'<code>{esc(f.parameter)}</code>' if f.parameter else ''}</p>
  {f'<p class="fix"><b>Fix:</b> {esc(f.remediation)}</p>' if f.remediation else ''}
  <p class="tags">{tags_block}</p>
</article>""")

    notes = "".join(f"<li>{esc(n)}</li>" for n in report.notes)
    tech = ", ".join(esc(x) for x in report.tech)
    gallery = ""
    for name, path in shots.items():
        uri = _b64_image(path)
        if uri:
            gallery += (f'<figure><img src="{uri}" alt="{esc(name)}">'
                        f'<figcaption>{esc(name)}</figcaption></figure>')

    clean = (f'<div class="clean">✅ {esc(t.get("report.clean"))}</div>'
             if not report.findings else "")

    return f"""<!doctype html>
<html lang="{t.code}" dir="{dir_attr}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PolyglotBugHunter-X — {esc(report.target)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:2rem 1rem; background:#0b0f17; color:#e6edf3;
         font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
  .wrap {{ max-width:1000px; margin:0 auto; }}
  header {{ border-bottom:1px solid #1f2937; padding-bottom:1rem; margin-bottom:1.5rem; }}
  h1 {{ font-size:1.6rem; margin:.2rem 0; }}
  h2 {{ font-size:1.15rem; margin:2rem 0 .8rem; }}
  h3 {{ font-size:1.02rem; margin:0 0 .5rem; }}
  .sub {{ color:#8b949e; font-size:.9rem; }}
  .pills {{ display:flex; flex-wrap:wrap; gap:.4rem; margin:.8rem 0; }}
  .pill {{ padding:.2rem .6rem; border-radius:99px; font-size:.8rem; font-weight:600; }}
  .risk {{ font-size:2.6rem; font-weight:800; line-height:1;
           background:linear-gradient(90deg,#8b5cf6,#ec4899);
           -webkit-background-clip:text; background-clip:text; color:transparent; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; }}
  .card {{ background:#111823; border:1px solid #1f2937; border-left:5px solid #555;
           border-radius:10px; padding:1rem 1.1rem; margin:.9rem 0; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:.5rem; align-items:center;
           font-size:.78rem; color:#8b949e; margin-bottom:.6rem; }}
  .score {{ color:#fff; font-weight:700; padding:.1rem .5rem; border-radius:6px; }}
  pre {{ background:#0a0e14; border:1px solid #1f2937; border-radius:8px; padding:.7rem;
         overflow:auto; font-size:.8rem; white-space:pre-wrap; word-break:break-word; }}
  .payload {{ color:#fca5a5; }} .req {{ color:#7dd3fc; }} .resp {{ color:#86efac; }}
  .proof {{ color:#fbbf24; font-size:.85rem; }}
  .impact,.fix {{ font-size:.9rem; }}
  .where {{ font-size:.8rem; color:#8b949e; }}
  .tag {{ background:#1f2937; border-radius:5px; padding:.1rem .45rem;
          font-size:.72rem; margin-right:.25rem; color:#c9d1d9; }}
  .shot {{ max-width:100%; border-radius:8px; border:1px solid #1f2937; margin:.6rem 0; }}
  .shot-missing {{ font-size:.75rem; color:#6b7280; font-family:monospace; }}
  .gallery {{ display:flex; gap:.8rem; flex-wrap:wrap; }}
  figure {{ margin:0; }} figure img {{ width:220px; border-radius:8px; border:1px solid #1f2937; }}
  figcaption {{ font-size:.72rem; color:#8b949e; }}
  .disclaimer {{ background:#1c1410; border:1px solid #7c2d12; color:#fdba74;
                padding:.7rem 1rem; border-radius:8px; font-size:.85rem; }}
  .clean {{ background:#0f2015; border:1px solid #14532d; color:#86efac;
            padding:1rem; border-radius:8px; }}
  .toc {{ columns:2; font-size:.85rem; }}
  .toc a {{ color:#8b5cf6; text-decoration:none; }} .toc a:hover {{ text-decoration:underline; }}
  footer {{ margin-top:2.5rem; padding-top:1rem; border-top:1px solid #1f2937;
            color:#6b7280; font-size:.78rem; }}
  [dir="rtl"] {{ text-align:right; }}
</style>
</head>
<body><div class="wrap">
<header>
  <h1>🕷️ PolyglotBugHunter-X</h1>
  <div class="sub">{esc(report.target)} · {_ts(report.started_at)} · {report.duration}s ·
     modes: {esc(', '.join(report.modes))}</div>
  <div class="risk">{report.risk_score}<span style="font-size:1rem">/100</span></div>
  <div class="pills">{sev_bars}</div>
  {f'<div class="sub">Stack: {tech}</div>' if tech else ''}
</header>

<p class="disclaimer">⚠️ {esc(t.get('report.disclaimer'))}</p>
{clean}

<h2>{esc(t.get('report.findings'))} ({len(report.findings)})</h2>
{''.join(cards)}

{'<h2>📝 Notes</h2><ul>' + notes + '</ul>' if notes else ''}
{'<h2>📸 Screenshots</h2><div class="gallery">' + gallery + '</div>' if gallery else ''}

<footer>
  schema {esc(report.schema_version)} · MIT · {esc(t.get('report.disclaimer'))}
</footer>
</div></body></html>"""


# --- json / sarif-lite ------------------------------------------------------


def to_json(report: ScanReport, indent: int = 2) -> str:
    return report.to_json(indent=indent)


def to_sarif(report: ScanReport) -> dict:
    """SARIF 2.1.0 subset. Uploaded results end up in code-scanning UIs."""
    rules: dict[str, dict] = {}

    def rule_for(f: Finding) -> dict:
        rid = (f.cwe or "PBHX-GENERIC").replace("CWE-", "")
        key = f"{rid}"
        if key not in rules:
            rules[key] = {
                "id": key,
                "name": f.title.split("(")[0].strip().replace(" ", "")[:60],
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "help": {"text": f.remediation or ""},
                "properties": {"tags": sorted(set(f.tags)) or ["security"],
                               "security-severity": str(f.cvss.score)},
            }
        return rules[key]

    results = []
    for f in report.findings:
        rule = rule_for(f)
        results.append({
            "ruleId": rule["id"],
            "level": {"critical": "error", "high": "error", "medium": "warning",
                      "low": "note", "info": "note"}[f.severity.value],
            "message": {"text": f.title + (f" — {f.evidence.proof}" if f.evidence.proof else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": (f.endpoint or f.url).replace("https://", "")},
                    "region": {"startLine": 1},
                },
            }],
            "properties": {
                "cvss": f.cvss.score, "vector": f.cvss.vector,
                "modality": f.modality.value, "confidence": f.confidence.value,
                "owasp": f.owasp, "cwe": f.cwe,
            },
            "partialFingerprints": {"pbhxFingerprint": f.fingerprint},
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "PolyglotBugHunter-X",
                "informationUri": "https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static",
                "version": "1.0.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


# --- writing ----------------------------------------------------------------


def save(report: ScanReport, out_dir: str | Path, lang: str = "en",
         screenshots: dict[str, str] | None = None,
         basename: str | None = None) -> dict[str, str]:
    """Write md + html + json + sarif. Returns the paths."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    stem = basename or f"pbhx-{int(report.started_at)}"
    # basename may itself contain a directory component; honour it
    if "/" in stem:
        d = d / stem.rsplit("/", 1)[0]
        d.mkdir(parents=True, exist_ok=True)
        stem = stem.rsplit("/", 1)[1]
    t = Translator(lang)
    paths = {
        "markdown": str(d / f"{stem}.md"),
        "html": str(d / f"{stem}.html"),
        "json": str(d / f"{stem}.json"),
        "sarif": str(d / f"{stem}.sarif"),
    }
    Path(paths["markdown"]).write_text(to_markdown(report, t, screenshots), encoding="utf-8")
    Path(paths["html"]).write_text(to_html(report, t, screenshots), encoding="utf-8")
    Path(paths["json"]).write_text(to_json(report), encoding="utf-8")
    Path(paths["sarif"]).write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
    return paths


def summarize(report: ScanReport, t: Translator | None = None) -> str:
    """One paragraph. Perfect for a CI step summary or a Gradio status line."""
    t = t or Translator("en")
    if not report.findings:
        return t.get("report.clean")
    counts = report.counts()
    top = report.sorted_findings()[0]
    parts = [f"{n} {t.severity(s)}" for s, n in counts.items() if n]
    return (f"{t.get('report.worst')}: {t.severity(report.worst.value).upper()} · "
            f"risk {report.risk_score}/100 · " + ", ".join(parts) +
            f" · top: {top.title}")
