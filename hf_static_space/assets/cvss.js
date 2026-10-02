// GENERATED FILE - do not edit.
// Produced by tools/build_static_space.py from the Python source of truth.
// Edit src/polyglot_bug_hunter/ or locales/, then re-run the generator.

// CVSS v3.1 base score, implemented from the published weights.
// Cross-checked against the Python original and the RedHat cvss library
// over 5000 random vectors (see tools/test_static_space.mjs).

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { H: 0.56, L: 0.22, N: 0.0 };
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.50 };

function roundup(x) {
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

export function cvss31(m) {
  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  if (iss <= 0) return 0.0;
  const changed = m.S === "C";
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const prWeight = (changed ? PR_CHANGED : PR_UNCHANGED)[m.PR];
  const exploitability = 8.22 * AV[m.AV] * AC[m.AC] * prWeight * UI[m.UI];
  if (impact <= 0) return 0.0;
  const raw = changed
    ? roundup(Math.min(1.08 * (impact + exploitability), 10))
    : roundup(Math.min(impact + exploitability, 10));
  return Math.round(raw * 10) / 10;
}

export function vectorOf(m) {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

export function severity(score) {
  if (score === 0) return "info";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

export const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function buildCvss(m) {
  const score = cvss31(m);
  return { vector: vectorOf(m), score, severity: severity(score) };
}
