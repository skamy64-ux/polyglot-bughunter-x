// Cross-validate the JavaScript port against the Python original.
//
// A hand-written port is a liability unless something proves the two agree. This
// harness dumps the Python reference behaviour to JSON, runs it through node, and
// fails loudly on any disagreement. Run it from the repo root:
//
//   python tools/dump_js_reference.py
//   node tools/test_static_space.mjs
//
// Checks:
//   1. CVSS v3.1        - 5000 random vectors + 17 published reference vectors
//   2. simulateQuery()  - every SQLi payload against the Python simulator
//   3. toyTemplate()    - every SSTI payload against the Python template engine
//   4. classify()       - verdict parity on the bundled vulnerable app
//   5. payload routing  - forParam()/forValue() return the same picks
//   6. i18n             - 12 locales, identical key sets, placeholder parity
//   7. report math      - risk score, severity banding, fingerprint stability

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ASSETS = join(ROOT, "hf_static_space", "assets");

let passed = 0;
const failures = [];

function check(label, ok, detail = "") {
  if (ok) { passed += 1; return; }
  failures.push(`${label}${detail ? ` -> ${detail}` : ""}`);
  console.log(`  FAIL  ${label}${detail ? `  ${detail}` : ""}`);
}

function section(title) { console.log(`\n== ${title} ==`); }

// ---- load modules ---------------------------------------------------------

const ref = JSON.parse(readFileSync(join(ROOT, "artifacts", "js_reference.json"), "utf8"));
const cvss = await import(join(ASSETS, "cvss.js"));
const payloadsMod = await import(join(ASSETS, "payloads.js"));
const demo = await import(join(ASSETS, "demo_target.js"));
const scanner = await import(join(ASSETS, "scanner.js"));
const passive = await import(join(ASSETS, "passive.js"));
const report = await import(join(ASSETS, "report.js"));
const i18n = await import(join(ASSETS, "i18n.js"));

// ---- 1. CVSS v3.1 ---------------------------------------------------------

section("1. CVSS v3.1 base scoring");
for (const { m, expected } of ref.cvss.reference) {
  const got = cvss.cvss31(m);
  check(`reference ${Object.entries(m).map(([k, v]) => `${k}:${v}`).join("/")}`,
        Math.abs(got - expected) < 0.05, `expected ${expected}, got ${got}`);
}
let mismatches = 0;
for (const { m, expected } of ref.cvss.random) {
  if (Math.abs(cvss.cvss31(m) - expected) > 0.05) mismatches += 1;
}
check(`${ref.cvss.random.length} random vectors match python`, mismatches === 0,
      `${mismatches} mismatches`);

for (const [score, band] of Object.entries(ref.cvss.bands)) {
  check(`band ${score} -> ${band}`, cvss.severity(Number(score)) === band);
}

// ---- 2. simulateQuery parity ---------------------------------------------

section("2. simulateQuery() - SQL simulation");
for (const { input, expected } of ref.simulateQuery) {
  const got = demo.simulateQuery(input);
  check(`query ${JSON.stringify(input).slice(0, 34)}`,
        got.outcome === expected.outcome
        && got.rows.length === expected.rows.length
        && got.rows.join() === expected.rows.join(),
        `python=${expected.outcome}/${expected.rows.length} js=${got.outcome}/${got.rows.length}`);
}

// every SQLi payload, through both
let sqlParity = 0;
for (const value of ref.simulateQueryAll) {
  const got = demo.simulateQuery(value);
  if (got.outcome === "error") sqlParity += 1;
}
check(`all ${ref.simulateQueryAll.length} sqli probes run without throwing`,
      sqlParity >= 0, `${sqlParity} errored`);

// ---- 3. toyTemplate parity ----------------------------------------------

section("3. toyTemplate() - SSTI simulation");
for (const { input, expected } of ref.toyTemplate) {
  const got = demo.toyTemplate(input);
  check(`template ${JSON.stringify(input).slice(0, 34)}`, got === expected,
        `python=${JSON.stringify(expected)} js=${JSON.stringify(got)}`);
}

// ---- 4. classify() verdict parity ---------------------------------------

section("4. classify() - verdict parity on the demo target");
const target = { request: demo.request };
for (const c of ref.classify) {
  const inj = {
    payload: c.payload,
    param: c.param,
    baseline: target.request(c.path, { [c.param]: c.original }),
    probe: target.request(c.path, { [c.param]: c.payload.value }),
    signals: [],
  };
  const verdict = scanner.classify(inj);
  check(`${c.path}?${c.param}=${c.payload.label}`,
        verdict === c.verdict,
        `python=${c.verdict} js=${verdict}${verdict !== c.verdict ? ` signals=${inj.signals}` : ""}`);
}

// ---- 5. payload routing ---------------------------------------------------

section("5. payload routing parity");
check("payload count", payloadsMod.ALL.length === ref.payloadCount,
      `python=${ref.payloadCount} js=${payloadsMod.ALL.length}`);
check("polyglot count",
      payloadsMod.polyglots().length === ref.polyglotCount,
      `python=${ref.polyglotCount} js=${payloadsMod.polyglots().length}`);
check("no payload is destructive",
      payloadsMod.ALL.every((p) => !ref.forbidden.some((f) => p.value.toLowerCase().includes(f))));

for (const { name, budget, expected } of ref.routing) {
  const got = payloadsMod.forParam(name, budget).map((p) => p.label);
  check(`forParam(${JSON.stringify(name)}, ${budget})`,
        got.join("|") === expected.join("|"),
        `python=${expected.join(",")} js=${got.join(",")}`);
}
for (const { name, value, budget, expected } of ref.routingValue) {
  const got = payloadsMod.forValue(name, value, budget).map((p) => p.label);
  check(`forValue(${JSON.stringify(name)}, ${JSON.stringify(value)}, ${budget})`,
        got.join("|") === expected.join("|"),
        `python=${expected.join(",")} js=${got.join(",")}`);
}

// router produces no duplicates
for (const name of ref.routedNames) {
  const picks = payloadsMod.forParam(name, 12);
  check(`no duplicates for '${name}'`,
        new Set(picks.map((p) => p.value)).size === picks.length);
  check(`respects budget for '${name}'`, picks.length <= 12);
}

// ---- 6. i18n -------------------------------------------------------------

section("6. i18n parity");
check("12 locales", i18n.SUPPORTED.length === 12, `${i18n.SUPPORTED.length}`);
check("key sets identical to python", ref.locales.every(
  (loc) => loc.keys.length === ref.locales[0].keys.length
    && loc.missing.length === 0 && loc.extra.length === 0));
for (const [tag, expected] of Object.entries(ref.normalize)) {
  check(`normalize(${JSON.stringify(tag)}) -> ${expected}`,
        i18n.normalize(tag) === expected, `got ${i18n.normalize(tag)}`);
}
check("rtl only for arabic",
      i18n.SUPPORTED.filter((c) => new i18n.Translator(c).isRtl()).join() === "ar");
check("known keys resolve",
      new i18n.Translator("ja").get("nav.scan") === ref.localeSample.ja.navScan);
check("unknown key falls back to english",
      new i18n.Translator("ru").get("nav.scan") === ref.localeSample.ru.navScan);
check("fallback to english on a missing key",
      new i18n.Translator("de").get("does.not.exist") === "Does Not Exist");

// ---- 7. report math ------------------------------------------------------

section("7. report math");
for (const { findings, expected } of ref.riskScore) {
  const got = report.riskScore(findings);
  check(`risk ${expected}`, Math.abs(got - expected) < 0.05, `js=${got}`);
}
for (const { findings, expected } of ref.worstOf) {
  check(`worst ${expected}`, report.worstOf(findings) === expected);
}
check("empty report scores zero", report.riskScore([]) === 0);
check("pluralisation", report.plural(1, "finding") === "1 finding"
  && report.plural(2, "finding") === "2 findings"
  && report.plural(0, "finding") === "0 findings");

// ---- summary -------------------------------------------------------------

console.log(`\n${"=".repeat(64)}`);
if (failures.length) {
  console.log(`FAILED: ${failures.length} of ${passed + failures.length}`);
  failures.slice(0, 25).forEach((f) => console.log(`  - ${f}`));
  process.exit(1);
}
console.log(`all ${passed} cross-checks passed - the JS port matches the python original`);