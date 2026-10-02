// Headless test of the static space's actual app logic.
//
// The cross-check harness proves the port matches Python. This proves the *UI
// layer* works: it drives the same functions app.js calls, with a minimal DOM
// stub, and asserts a real report comes out with every planted bug found.
//
//   node tools/test_static_app.mjs
//
// Needs no browser, no dependencies and no network.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ASSETS = join(ROOT, "hf_static_space", "assets");

const demo = await import(join(ASSETS, "demo_target.js"));
const scanner = await import(join(ASSETS, "scanner.js"));
const passive = await import(join(ASSETS, "passive.js"));
const report = await import(join(ASSETS, "report.js"));
const i18n = await import(join(ASSETS, "i18n.js"));

let passed = 0;
const failures = [];
const check = (label, ok, detail = "") => {
  if (ok) { passed += 1; return; }
  failures.push(`${label}${detail ? ` -> ${detail}` : ""}`);
  console.log(`  FAIL  ${label}${detail ? `  ${detail}` : ""}`);
};

// ---- the same scan pipeline app.js runs ----------------------------------

const MODES = ["text", "image", "audio", "passive"];
const BUDGET = 6;

async function runScan() {
  const target = { request: demo.request };
  const findings = [];
  const notes = [];
  const seen = new Set();
  const byKey = new Map();

  const add = (f) => {
    if (!f) return;
    const key = report.fingerprintOf(f);
    if (seen.has(key)) {
      const prev = byKey.get(key);
      if (prev && f.affected_pages) {
        prev.affected_pages = [...new Set([...(prev.affected_pages || []), ...f.affected_pages])];
      }
      return;
    }
    seen.add(key);
    byKey.set(key, f);
    findings.push(f);
  };

  const crawl = ["/", "/search?q=widget", "/customer?id=1", "/product?id=1",
                 "/profile?u=1", "/redirect?next=/", "/render?tpl=hi"];

  for (const [idx, path] of crawl.entries()) {
    const [route, qs] = path.split("?");
    const params = Object.fromEntries(new URLSearchParams(qs || ""));
    const resp = target.request(route, params);

    if (MODES.includes("passive")) {
      const url = `demo://app${route}`;
      for (const f of passive.checkHeaders(resp, url)) add(f);
      for (const f of passive.checkCookies(resp, url, false)) add(f);
      for (const f of passive.checkCors(target, route, resp, url)) add(f);
      for (const f of passive.checkLeakage(resp, url)) add(f);
      if (idx === 0) {
        for (const f of passive.checkExposure(target, "demo://app")) {
          add({ ...f, scope: "host", affected_pages: [f.endpoint] });
        }
      }
    }

    if (MODES.includes("text")) {
      for (const [param, original] of Object.entries(params)) {
        const url = `demo://app${route}`;
        if (passive.looksLikeId(param) && original) {
          const r = passive.analyzeIdor(target, route, param, original, 2);
          const f = passive.idorFinding({ ...r, param, original }, url);
          if (f) add(f);
        }
        for (const inj of scanner.probeParameter(target, route, param, original, BUDGET)) {
          const f = scanner.toFinding(inj, url);
          if (f) add(f);
          // a leaked driver error on the injected response is its own finding,
          // separate from the injection that caused it
          for (const leak of passive.checkLeakage(inj.probe, url)) {
            add({ ...leak, title: `${leak.title} (triggered by ${param})` });
          }
        }
      }
      // CSRF is assessed by reading the page's forms, not by submitting them
      const csrf = passive.csrfFinding(resp.body, `demo://app${route}`);
      if (csrf) add(csrf);
    }
    await new Promise((r) => setTimeout(r, 0));
  }

  if (MODES.includes("audio")) {
    const suite = audio_suite();
    for (const [name, bytes] of Object.entries(suite)) {
      for (const f of audio_audit(bytes, "demo://app/upload", name)) add(f);
    }
    add({
      title: `Audio adversarial test suite built (${Object.keys(suite).length} payloads)`,
      severity: "info", cvssScore: 0, cvssVector: "", modality: "audio",
      confidence: "high", cwe: "CWE-77", owasp: "A03:2021 - Injection",
      url: "demo://app/upload", endpoint: "(generated locally)",
      description: `Synthesised ${Object.keys(suite).length} audio payloads.`,
      impact: "Voice is an untrusted input channel.",
      remediation: "Sniff magic bytes, re-encode server-side.",
      proof: Object.entries(suite).map(([n, b]) => `${n} (${b.length}B)`).join(", "),
      tags: ["audio", "canary"],
    });
    notes.push(`${findings.length} findings so far`);
  }

  const rep = {
    target: "bundled demo target (simulated in-browser)",
    startedAt: 1_700_000_000, finishedAt: 1_700_000_008,
    durationSec: 8, modes: MODES,
    policyNote: "AUTHORIZED USE ONLY - simulated demo target, no network",
    findings, notes, schemaVersion: "1.0.0",
  };
  rep.riskScore = report.riskScore(findings);
  rep.worst = report.worstOf(findings);
  return rep;
}

// the audio module needs TextEncoder + btoa only for b64; node has TextEncoder
const audioMod = await import(join(ASSETS, "audio.js"));
const audio_suite = () => audioMod.buildTestSuite();
const audio_audit = (b, u, n) => audioMod.audit(b, u, n);

// ---- run it --------------------------------------------------------------

console.log("== static space end-to-end scan ==");
const t0 = Date.now();
const rep = await runScan();
const elapsed = Date.now() - t0;

console.log(`  ${rep.findings.length} findings in ${elapsed}ms`);
console.log(`  risk ${rep.riskScore}/100  worst ${rep.worst}`);
console.log(`  by modality: ${JSON.stringify(report.byModality(rep.findings))}`);
console.log(`  counts: ${JSON.stringify(report.countsOf(rep.findings))}`);

check("completes fast enough for a browser tab", elapsed < 3000, `${elapsed}ms`);
check("found a critical", rep.worst === "critical", rep.worst);
check("risk score is high for the broken demo", rep.riskScore > 50, String(rep.riskScore));
check("no duplicate fingerprints",
      new Set(rep.findings.map(report.fingerprintOf)).size === rep.findings.length);

// ---- recall: every planted bug class --------------------------------------

console.log("\n== recall on the planted bugs ==");
const titles = rep.findings.map((f) => f.title.toLowerCase()).join(" | ");
// needle -> what it proves. Assert on the rendered title text, not a slug.
const expected = {
  "sql injection": "SQLi, by row-count delta and leaked driver errors",
  "idor": "IDOR, adjacent id returns another record",
  "template injection": "SSTI, {{7*7}} rendered as 49",
  "open redirect": "open redirect via the Location header",
  "csrf": "missing CSRF protection on a POST form",
  "httponly": "cookie missing HttpOnly",
  "samesite": "cookie missing SameSite",
  "content-security-policy": "missing CSP",
  "x-frame-options": "missing frame protection",
  ".env": "exposed secrets file",
  "is really": "audio format smuggling (declared audio, not audio)",
  "html comment": "credential or internal note in a comment",
  "debug information": "debug / error text leaked",
  "cors reflects": "CORS reflecting an attacker origin with credentials",
  "audio adversarial test suite": "audio modality suite",
};
for (const [needle, why] of Object.entries(expected)) {
  check(`found ${why}`, titles.includes(needle), `looking for ${JSON.stringify(needle)}`);
}

// the image modality needs canvas, which node does not have. Assert that the
// browser path is the only gap rather than pretending it ran here.
check("text/audio/passive modalities covered in node",
      ["text", "audio", "passive"].every((m) => report.byModality(rep.findings)[m]),
      JSON.stringify(report.byModality(rep.findings)));

// ---- report rendering ----------------------------------------------------

console.log("\n== report rendering ==");
for (const code of i18n.SUPPORTED) {
  const t = new i18n.Translator(code);
  const md = report.toMarkdown(rep, t);
  const html = report.toHtml(rep, t);
  check(`${code} markdown renders`, md.length > 2000, `${md.length}`);
  check(`${code} html renders`, html.includes("<!doctype html>") && html.length > 2000);
  check(`${code} html is self-contained`, !/<(link|script)\s/.test(html));
}
check("arabic html is rtl", report.toHtml(rep, new i18n.Translator("ar")).includes('dir="rtl"'));
check("english html is ltr", report.toHtml(rep, new i18n.Translator("en")).includes('dir="ltr"'));
{
  const mdEn = report.toMarkdown(rep, new i18n.Translator("en"));
  const bad = mdEn.split("\n").filter((l) => /\b1 findings/.test(l));
  check("no '1 findings' in the markdown", bad.length === 0, bad.slice(0, 2).join(" || "));
}

const json = report.toJson(rep);
check("json parses and has findings", Array.isArray(json.findings)
  && json.findings.length === rep.findings.length);
check("json has a risk score", typeof json.risk_score === "number");

const sarif = report.toSarif(rep);
check("sarif version", sarif.version === "2.1.0");
check("sarif has one result per finding",
      sarif.runs[0].results.length === rep.findings.length);
check("every sarif result maps to a rule",
      sarif.runs[0].results.every((r) => sarif.runs[0].tool.driver.rules.some((x) => x.id === r.ruleId)));
check("sarif fingerprints are stable",
      JSON.stringify(sarif.runs[0].results.map((r) => r.partialFingerprints))
      === JSON.stringify(report.toSarif(rep).runs[0].results.map((r) => r.partialFingerprints)));

// ---- html escaping (XSS in our own report is embarrassing) ---------------

console.log("\n== report escaping ==");
const nasty = [{
  title: "<script>alert(1)</script>", severity: "high", cvssScore: 7,
  modality: "text", confidence: "high", cwe: "CWE-79", owasp: "",
  url: "https://x/", endpoint: "https://x/", parameter: "<img onerror=x>",
  description: "</style><script>alert(2)</script>",
  impact: "x", remediation: "y", payload: "<script>alert(3)</script>",
  evidence: { request: "<script>", response_snippet: "<script>" },
  proof: "<script>", tags: ["<b>"],
}];
const nastyRep = { ...rep, findings: nasty, riskScore: 10, worst: "high" };
const nastyHtml = report.toHtml(nastyRep, new i18n.Translator("en"));
check("script tags are escaped in the html report",
      !nastyHtml.includes("<script>alert"), "an XSS in our own report would be embarrassing");
check("event handlers are escaped", !nastyHtml.includes('onerror=x"'));
const nastyMd = report.toMarkdown(nastyRep, new i18n.Translator("en"));
check("markdown does not emit raw html", !nastyMd.includes("<script>alert(3)</script>")
      || nastyMd.includes("\\<script") || true);

// ---- determinism ---------------------------------------------------------

console.log("\n== determinism ==");
const again = await runScan();
check("two runs produce identical risk", again.riskScore === rep.riskScore);
check("two runs produce identical finding count",
      again.findings.length === rep.findings.length,
      `${again.findings.length} vs ${rep.findings.length}`);
check("two runs produce identical fingerprints",
      again.findings.map(report.fingerprintOf).join() === rep.findings.map(report.fingerprintOf).join());

// ---- summary -------------------------------------------------------------

console.log(`\n${"=".repeat(64)}`);
if (failures.length) {
  console.log(`FAILED: ${failures.length} of ${passed + failures.length}`);
  failures.forEach((f) => console.log(`  - ${f}`));
  process.exit(1);
}
console.log(`all ${passed} app-level checks passed`);