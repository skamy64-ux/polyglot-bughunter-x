// PolyglotBugHunter-X - report rendering (markdown, HTML, JSON, SARIF).
//
// Ported from report/render.py. The HTML report is a single self-contained
// string with no external assets, because the whole point is that a visitor can
// save it, email it, and have it open correctly offline.

import { SEV_RANK, severity as cvssSeverity } from "./cvss.js";

export const SEV_ICON = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };
export const SEV_COLOR = {
  critical: "#b91c1c", high: "#c2410c", medium: "#a16207", low: "#1d4ed8", info: "#4b5563",
};
export const MODALITY_ICON = { text: "⌨️", image: "🖼️", audio: "🎙️", passive: "👁️" };
export const ORDER = ["critical", "high", "medium", "low", "info"];

export function plural(n, singular, many) {
  return `${n} ${n === 1 ? singular : (many || `${singular}s`)}`;
}

export function countsOf(findings) {
  const out = {};
  for (const s of ORDER) out[s] = 0;
  for (const f of findings) out[f.severity] = (out[f.severity] || 0) + 1;
  return out;
}

export function byModality(findings) {
  const out = {};
  for (const f of findings) out[f.modality] = (out[f.modality] || 0) + 1;
  return out;
}

export function worstOf(findings) {
  let worst = "info";
  for (const f of findings) {
    if ((SEV_RANK[f.severity] || 1) > (SEV_RANK[worst] || 1)) worst = f.severity;
  }
  return worst;
}

/** Saturating 0-100 rollup. One critical lands near 19, not near 100. */
export function riskScore(findings) {
  if (!findings.length) return 0;
  const W = { critical: 25, high: 12, medium: 5, low: 2, info: 0.5 };
  const C = { high: 1.0, medium: 0.75, low: 0.45 };
  let raw = 0;
  for (const f of findings) {
    raw += (W[f.severity] || 0.5) * (C[f.confidence] ?? 1.0);
  }
  return Math.round(100 * (1 - Math.exp(-raw / 120)) * 10) / 10;
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) => (SEV_RANK[b.severity] - SEV_RANK[a.severity])
    || ((b.cvssScore || 0) - (a.cvssScore || 0)));
}

const ts = (epoch) => new Date(epoch * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";

// ---- markdown -------------------------------------------------------------

export function toMarkdown(report, t) {
  const counts = countsOf(report.findings);
  const lines = [];
  const g = (k, f) => (t ? t.get(k, f) : k);

  lines.push(`# 🕷️ PolyglotBugHunter-X report — \`${report.target}\``);
  lines.push("");
  lines.push(`**${g("report.worst")}: ${SEV_ICON[report.worst]} ${t ? t.severity(report.worst) : report.worst.toUpperCase()}**`
    + ` · risk **${report.riskScore}/100**`
    + ` · ${plural(report.findings.length, "finding")}`
    + ` · ${report.durationSec}s · ${report.modes.join(", ")}`);
  lines.push("");
  lines.push(`> 🧨 ${g("report.disclaimer")}`);
  lines.push("");

  lines.push(`| ${ORDER.map((s) => `${t ? t.severity(s) : s} (${counts[s]})`).join(" | ")} |`);
  lines.push(`| ${ORDER.map(() => "---:").join(" | ")} |`);
  lines.push(`| ${ORDER.map((s) => `**${counts[s]}**`).join(" | ")} |`);
  lines.push("");

  if (report.tech?.length) lines.push(`**Stack:** ${report.tech.join(", ")}  `);
  else lines.push("*Stack: not fingerprinted from headers or markup.*  ");
  if (report.policyNote) lines.push(`**Scope/authorization:** \`${report.policyNote}\`  `);
  lines.push(`**Scanned:** ${ts(report.startedAt)}  `);
  lines.push(`**Modes:** ${report.modes.join(", ")}`);
  lines.push("");

  const mods = byModality(report.findings);
  if (Object.keys(mods).length > 1) {
    lines.push("## 🧪 Modality coverage");
    lines.push("");
    for (const [m, n] of Object.entries(mods).sort((x, y) => y[1] - x[1])) {
      lines.push(`- ${MODALITY_ICON[m] || "•"} **${m}** — ${plural(n, "finding")}`);
    }
    lines.push("");
  }

  if (!report.findings.length) {
    lines.push(`## ✅ ${g("report.clean")}`);
    lines.push("");
    lines.push("No injection or misconfiguration signal was detected within the "
      + "configured budget. That is not proof of safety — it means the specific "
      + "probes sent did not trip. Keep an eye on the notes below.");
    lines.push("");
  } else {
    sortFindings(report.findings).forEach((f, i) => lines.push(findingMd(f, i + 1, t)));
    lines.push("");
  }

  if (report.notes?.length) {
    lines.push("## 📝 Notes");
    lines.push("");
    lines.push(...report.notes.map((n) => `- ${n}`));
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push(`<sub>PolyglotBugHunter-X · schema ${report.schemaVersion} · ${ts(report.finishedAt)} · MIT licensed · report responsibly</sub>`);
  return lines.join("\n");
}

function findingMd(f, n, t) {
  const out = [];
  const sevLabel = t ? t.severity(f.severity) : f.severity;
  out.push(`### ${SEV_ICON[f.severity] || "•"} ${n}. ${f.title}`);
  out.push("");
  out.push(`\`${f.cvssScore ?? ""}\` **${sevLabel.toUpperCase()}** · `
    + `${MODALITY_ICON[f.modality] || "•"} ${f.modality} · `
    + `confidence \`${f.confidence}\``
    + (f.cwe ? ` · ${f.cwe}` : "")
    + (f.owasp ? ` · ${f.owasp}` : "")
    + (f.cvssVector ? ` · CVSS \`${f.cvssVector}\`` : ""));
  out.push("");
  if (f.description) { out.push(f.description, ""); }
  if (f.impact) { out.push(`**Impact:** ${f.impact}`, ""); }
  if (f.payload) { out.push("**Payload used**", "", "```", f.payload, "```", ""); }
  if (f.evidence) {
    out.push("**Evidence**", "");
    if (f.evidence.request) { out.push("```http", f.evidence.request, "```", ""); }
    if (f.evidence.response_snippet) {
      out.push("```", f.evidence.response_snippet.slice(0, 600), "```", "");
    }
    if (f.proof) { out.push(`**Proof:** ${f.proof}`, ""); }
  }
  if (f.endpoint || f.parameter) {
    out.push(`**Where:** \`${f.endpoint || f.url}\``
      + (f.parameter ? ` · parameter \`${f.parameter}\`` : ""), "");
  }
  if (f.remediation) {
    out.push("**Fix**", "", `1. ${f.remediation}`, "2. Add a regression test that replays this exact payload.", "");
  }
  if (f.tags?.length) out.push(`\`${[...new Set(f.tags)].sort().join("` `")}\``, "");
  return out.join("\n");
}

// ---- HTML -----------------------------------------------------------------

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" }[c]
));

export function toHtml(report, t) {
  const counts = countsOf(report.findings);
  const dir = t && t.isRtl() ? "rtl" : "ltr";
  const g = (k) => (t ? t.get(k) : k);

  const pills = ORDER.map((s) => `<span class="pill" style="background:${SEV_COLOR[s]}">`
    + `${SEV_ICON[s]} ${esc(t ? t.severity(s) : s)} ${counts[s]}</span>`).join("");

  const cards = sortFindings(report.findings).map((f, i) => `
<article class="card" style="border-left-color:${SEV_COLOR[f.severity]}">
  <h3>${SEV_ICON[f.severity] || "•"} ${i + 1}. ${esc(f.title)}</h3>
  <div class="meta">
    <span class="score" style="background:${SEV_COLOR[f.severity]}">${f.cvssScore ?? ""}</span>
    <span>${MODALITY_ICON[f.modality] || "•"} ${esc(f.modality)}</span>
    <span>conf: ${esc(f.confidence)}</span>
    ${f.cwe ? `<span>${esc(f.cwe)}</span>` : ""}
    ${f.owasp ? `<span>${esc(f.owasp)}</span>` : ""}
    ${f.cvssVector ? `<code>${esc(f.cvssVector)}</code>` : ""}
  </div>
  <p>${esc(f.description)}</p>
  ${f.impact ? `<p class="impact"><b>Impact:</b> ${esc(f.impact)}</p>` : ""}
  ${f.payload ? `<pre class="payload">${esc(f.payload)}</pre>` : ""}
  ${f.evidence?.request ? `<pre class="req"><b>request</b>\n${esc(f.evidence.request.slice(0, 900))}</pre>` : ""}
  ${f.evidence?.response_snippet ? `<pre class="resp"><b>response</b>\n${esc(f.evidence.response_snippet.slice(0, 900))}</pre>` : ""}
  ${f.proof ? `<p class="proof"><b>proof:</b> ${esc(f.proof)}</p>` : ""}
  <p class="where"><code>${esc(f.endpoint || f.url)}</code>${f.parameter ? ` <code>${esc(f.parameter)}</code>` : ""}</p>
  ${f.remediation ? `<p class="fix"><b>Fix:</b> ${esc(f.remediation)}</p>` : ""}
  <p class="tags">${[...new Set(f.tags || [])].map((x) => `<span class="tag">${esc(x)}</span>`).join("")}</p>
</article>`).join("");

  const notes = (report.notes || []).map((n) => `<li>${esc(n)}</li>`).join("");
  const clean = report.findings.length
    ? ""
    : `<div class="clean">✅ ${esc(g("report.clean"))}</div>`;

  return `<!doctype html>
<html lang="${t ? t.code : "en"}" dir="${dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PolyglotBugHunter-X — ${esc(report.target)}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; padding:2rem 1rem; background:#0b0f17; color:#e6edf3;
         font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:1000px; margin:0 auto; }
  header { border-bottom:1px solid #1f2937; padding-bottom:1rem; margin-bottom:1.5rem; }
  h1 { font-size:1.6rem; margin:.2rem 0; }
  h2 { font-size:1.15rem; margin:2rem 0 .8rem; }
  h3 { font-size:1.02rem; margin:0 0 .5rem; }
  .sub { color:#8b949e; font-size:.9rem; }
  .pills { display:flex; flex-wrap:wrap; gap:.4rem; margin:.8rem 0; }
  .pill { padding:.2rem .6rem; border-radius:99px; font-size:.8rem; font-weight:600; color:#fff; }
  .risk { font-size:2.6rem; font-weight:800; line-height:1;
          background:linear-gradient(90deg,#8b5cf6,#ec4899);
          -webkit-background-clip:text; background-clip:text; color:transparent; }
  .card { background:#111823; border:1px solid #1f2937; border-left:5px solid #555;
          border-radius:10px; padding:1rem 1.1rem; margin:.9rem 0; }
  .meta { display:flex; flex-wrap:wrap; gap:.5rem; align-items:center;
          font-size:.78rem; color:#8b949e; margin-bottom:.6rem; }
  .score { color:#fff; font-weight:700; padding:.1rem .5rem; border-radius:6px; }
  pre { background:#0a0e14; border:1px solid #1f2937; border-radius:8px; padding:.7rem;
        overflow:auto; font-size:.8rem; white-space:pre-wrap; word-break:break-word; }
  .payload { color:#fca5a5; } .req { color:#7dd3fc; } .resp { color:#86efac; }
  .proof { color:#fbbf24; font-size:.85rem; }
  .impact,.fix { font-size:.9rem; }
  .where { font-size:.8rem; color:#8b949e; }
  .tag { background:#1f2937; border-radius:5px; padding:.1rem .45rem;
         font-size:.72rem; margin-right:.25rem; color:#c9d1d9; }
  .disclaimer { background:#1c1410; border:1px solid #7c2d12; color:#fdba74;
                padding:.7rem 1rem; border-radius:8px; font-size:.85rem; }
  .clean { background:#0f2015; border:1px solid #14532d; color:#86efac;
           padding:1rem; border-radius:8px; }
  footer { margin-top:2.5rem; padding-top:1rem; border-top:1px solid #1f2937;
           color:#6b7280; font-size:.78rem; }
  [dir="rtl"] { text-align:right; }
</style>
</head>
<body><div class="wrap">
<header>
  <h1>🕷️ PolyglotBugHunter-X</h1>
  <div class="sub">${esc(report.target)} · ${ts(report.startedAt)} · ${report.durationSec}s ·
     modes: ${esc(report.modes.join(", "))}</div>
  <div class="risk">${report.riskScore}<span style="font-size:1rem">/100</span></div>
  <div class="pills">${pills}</div>
</header>

<p class="disclaimer">⚠️ ${esc(g("report.disclaimer"))}</p>
${clean}

<h2>${esc(g("report.findings"))} (${report.findings.length})</h2>
${cards}

${notes ? `<h2>📝 Notes</h2><ul>${notes}</ul>` : ""}

<footer>schema ${esc(report.schemaVersion)} · MIT · ${esc(g("report.disclaimer"))}</footer>
</div></body></html>`;
}

// ---- JSON -----------------------------------------------------------------

export function toJson(report) {
  return {
    target: report.target,
    toolkit: "PolyglotBugHunter-X",
    schema_version: report.schemaVersion,
    started_at: report.startedAt,
    finished_at: report.finishedAt,
    duration_sec: report.durationSec,
    modes: report.modes,
    policy_note: report.policyNote,
    risk_score: report.riskScore,
    worst_severity: report.worst,
    counts: countsOf(report.findings),
    by_modality: byModality(report.findings),
    findings: sortFindings(report.findings).map((f) => ({
      ...f,
      fingerprint: fingerprintOf(f),
    })),
    notes: report.notes || [],
  };
}

/** Stable id so the same bug is not reported twice across runs. */
export function fingerprintOf(f) {
  const raw = `${f.cwe || f.title}|${f.endpoint || f.url}|${f.parameter || ""}|${f.title}`;
  // FNV-1a, hex. Not cryptographic; it only needs to be stable.
  let h = 0x811c9dc5;
  for (let i = 0; i < raw.length; i += 1) {
    h ^= raw.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

// ---- SARIF ----------------------------------------------------------------

export function toSarif(report) {
  const rules = {};
  for (const f of report.findings) {
    const id = (f.cwe || "PBHX-GENERIC").replace("CWE-", "");
    if (!rules[id]) {
      rules[id] = {
        id,
        name: f.title.split("(")[0].trim().replace(/\s+/g, "") || id,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description || f.title },
        help: { text: f.remediation || "" },
        properties: { tags: [...new Set(f.tags || ["security"])].sort(),
                       "security-severity": String(f.cvssScore ?? "") },
      };
    }
  }
  const level = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "PolyglotBugHunter-X",
          informationUri: "https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static",
          version: "1.0.0",
          rules: Object.values(rules),
        },
      },
      results: sortFindings(report.findings).map((f) => ({
        ruleId: (f.cwe || "PBHX-GENERIC").replace("CWE-", ""),
        level: level[f.severity],
        message: { text: `${f.title}${f.proof ? ` — ${f.proof}` : ""}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: String(f.endpoint || f.url).replace("https://", "") },
            region: { startLine: 1 },
          },
        }],
        properties: {
          cvss: f.cvssScore, vector: f.cvssVector, modality: f.modality,
          confidence: f.confidence, owasp: f.owasp, cwe: f.cwe,
        },
        partialFingerprints: { pbhxFingerprint: fingerprintOf(f) },
      })),
    }],
  };
}

// ---- one-liner for CI / status lines --------------------------------------

export function summarize(report, t) {
  if (!report.findings.length) return t ? t.get("report.clean") : "No findings.";
  const counts = countsOf(report.findings);
  const top = sortFindings(report.findings)[0];
  const parts = ORDER.filter((s) => counts[s]).map((s) => `${counts[s]} ${t ? t.severity(s) : s}`);
  const worst = t ? t.severity(report.worst) : report.worst.toUpperCase();
  return `${worst} · risk ${report.riskScore}/100 · ${parts.join(", ")} · top: ${top.title}`;
}

export { cvssSeverity };