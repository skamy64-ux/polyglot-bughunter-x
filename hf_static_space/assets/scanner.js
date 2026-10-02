// PolyglotBugHunter-X - detection engine.
//
// Ported from scanner/text.py, scanner/passive.py and scanner/access.py. The
// verdicts are the interesting part and they are *differential*: a single probe
// proves nothing, plenty of apps echo input without being vulnerable. What
// proves it is a shape - a row count that moves, a rendered {{7*7}}, shell
// output in the body, an unescaped reflection.
//
// Every positive verdict carries the signal that produced it, so a report can be
// argued about with evidence instead of vibes.

import { MARKER, forValue } from "./payloads.js";
import { escapeHtml } from "./demo_target.js";

// ---------------------------------------------------------------- verdicts

export const VERDICT = {
  VULNERABLE: "vulnerable",
  SUSPICIOUS: "suspicious",
  CLEAN: "clean",
  BLOCKED: "blocked",
  ERROR: "error",
};

// ---- tell-tale strings, ported verbatim -----------------------------------

const SQL_ERRORS = [
  "sql syntax", "mysql_fetch", "mysql_num_rows", "you have an error in your sql",
  "warning: mysql", "pg_query", "postgresql", "sqlite3", "sqlite::",
  "ora-00933", "ora-01756", "odbc driver", "microsoft ole db provider",
  "unclosed quotation mark", "syntax error at or near", "supplied argument is not",
  "valid mysql result", "operand should contain", "column count", "ambiguous column",
  "java.sql.sqlexception", "quoted string not properly terminated",
  "com.mysql.jdbc.exceptions", "hibernate", "jdbc", "unsupported sql",
];

const SSTI_ARITH = {
  "{7*7}": "49", "${7*7}": "49", "<%= 7*7 %>": "49", "<%= 7 * 7 %>": "49",
  "{7*'7'}": "77777749", "{8*8}": "64", "${8*8}": "64", "#{7*7}": "49",
  "{{7*7}}": "49",
};

const COMMAND_OUTPUT = /(uid=\d+\(|root:|www-data:|nobody:|bin\/sh|bin\/bash|command not found|^\s*total\s+\d+|\bwindows\s+system32\b)/gmi;

const WAF_HINTS = ["cloudflare", "sucuri", "akamai", "incapsula", "modsecurity",
                   "awswaf", "imperva", "fortiweb", "wallarm", "distil"];

// ---- helpers --------------------------------------------------------------

export function rowCount(body) {
  if (!body) return 0;
  const counts = [
    (body.match(/<tr\b/gi) || []).length,
    (body.match(/<li\b/gi) || []).length,
    (body.match(/class="[^"]*(?:card|item|result|post|row|tile)[^"]*"/gi) || []).length,
    (body.match(/"(?:id|uuid|email|name)"\s*:/g) || []).length,
    (body.match(/<article\b/gi) || []).length,
  ];
  return Math.max(0, ...counts);
}

export function bodyShape(resp) {
  const b = (resp && resp.body) || "";
  return { length: b.length, rows: rowCount(b) };
}

function unescapedReflection(baseline, probe, marker) {
  if (!probe || !probe.body.includes(marker)) return false;
  if (baseline && baseline.body.includes(marker)) return false;
  const i = probe.body.indexOf(marker);
  const around = probe.body.slice(Math.max(0, i - 60), i + 200);
  const escaped = ["&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "\\u003c"]
    .some((e) => around.includes(e));
  return !escaped;
}

function hasPayloadReflected(probe, value) {
  if (!probe) return false;
  const hay = (probe.body || "").replace(/\s+/g, " ");
  const needle = String(value || "").replace(/\s+/g, "");
  if (needle.length < 6) return needle ? hay.includes(needle) : false;

  // The python original uses difflib.SequenceMatcher and asks whether any
  // matching block is >= max(8, 60% of the payload). Equivalently: does any
  // substring of that length appear verbatim in the body? The body is capped
  // because a full quadratic LCS over a 200KB page is not worth the CPU.
  const budget = Math.max(8, Math.ceil(needle.length * 0.6));
  const hayCapped = hay.slice(0, 200000);
  // longest-first: usually the full-length probe hits immediately
  for (let len = needle.length; len >= budget; len -= 1) {
    for (let i = 0; i + len <= needle.length; i += 1) {
      if (hayCapped.includes(needle.slice(i, i + len))) return true;
    }
  }
  return false;
}

// ---- the classifier -------------------------------------------------------

/**
 * @param {object} inj  { payload, param, baseline, probe }
 * @returns {string} one of VERDICT
 */
export function classify(inj) {
  const { payload: p, probe, baseline } = inj;
  const signals = inj.signals || (inj.signals = []);
  if (!probe) return VERDICT.ERROR;

  // a 4xx/5xx is *data* - it's often the whole proof. status 0 is a transport
  // failure and tells us nothing.
  if (probe.status === 0 && probe.error) {
    signals.push(`request error: ${probe.error}`);
    return VERDICT.ERROR;
  }

  // 404 on a parameter the baseline accepted means the app looked the value up
  // and did not find it. Correct behaviour, not a filter bypass.
  if ((probe.status === 404 || probe.status === 410)
      && baseline.status !== 404 && baseline.status !== 410) {
    return VERDICT.CLEAN;
  }

  // WAF ate it: inconclusive, never "clean"
  if ([403, 406, 429, 503].includes(probe.status)
      && ![403, 429].includes(baseline.status)) {
    const low = (probe.body || "").toLowerCase();
    if (probe.status === 403 || probe.status === 429 || WAF_HINTS.some((h) => low.includes(h))) {
      signals.push(`blocked by WAF (HTTP ${probe.status})`);
      return VERDICT.BLOCKED;
    }
  }

  const low = (probe.body || "").toLowerCase();
  const vp = p.vuln;

  // 1. SSTI arithmetic - strongest single signal there is
  if (vp === "ssti") {
    const expect = SSTI_ARITH[String(p.value).trim()];
    if (expect && low.includes(expect)) {
      signals.push(`template rendered ${p.value} -> ${expect}`);
      return VERDICT.VULNERABLE;
    }
    if (/7\*7|\$\{|<%=/.test((probe.body || "").slice(0, 20000))) {
      signals.push("template syntax echoed - engine may be Jinja/Twig");
      return VERDICT.SUSPICIOUS;
    }
  }

  // 2. command output actually executed
  if (vp === "cmdi") {
    const mine = (probe.body || "").match(COMMAND_OUTPUT);
    const theirs = (baseline.body || "").match(COMMAND_OUTPUT);
    if (mine && !theirs) {
      signals.push("shell output in response (uid=/root:/windows)");
      return VERDICT.VULNERABLE;
    }
    if (p.label === "crlf-newline" && probe.status >= 400 && baseline.status < 400) {
      signals.push("CRLF broke the response (status flip)");
      return VERDICT.SUSPICIOUS;
    }
  }

  // 3. SQL: error text, then boolean differential, then status flip
  if (vp === "sqli") {
    const baseLow = (baseline.body || "").toLowerCase();
    const err = SQL_ERRORS.find((e) => low.includes(e) && !baseLow.includes(e));
    if (err) {
      signals.push(`db error leaked: '${err}'`);
      return VERDICT.VULNERABLE;
    }
    if (probe.status >= 500 && baseline.status < 500) {
      signals.push(`5xx on injection (${baseline.status} -> ${probe.status})`);
      return VERDICT.VULNERABLE;
    }
    if (p.label.startsWith("tautology") || p.label === "union-null") {
      const a = rowCount(baseline.body);
      const b = rowCount(probe.body);
      if (a && b && b > a) {
        signals.push(`row count grew ${a} -> ${b} on a tautology`);
        return VERDICT.VULNERABLE;
      }
      if (a && b === 0 && a > 2) {
        signals.push("row count collapsed to 0");
        return VERDICT.SUSPICIOUS;
      }
    }
    if (p.label === "order-by-probe" && probe.status >= 500 && baseline.status < 500) {
      signals.push("column count out of range error");
      return VERDICT.VULNERABLE;
    }
  }

  // 4. traversal: real file markers
  if (vp === "traversal") {
    if (low.includes("root:x:") || low.includes("[fonts]")) {
      signals.push("etc/passwd or win.ini contents in response");
      return VERDICT.VULNERABLE;
    }
    if (probe.status === 200 && !/404/.test((probe.body || "").slice(0, 400))
        && baseline.status >= 400) {
      signals.push(`traversal returned 200 (baseline ${baseline.status})`);
      return VERDICT.SUSPICIOUS;
    }
  }

  // 5. ssrf / redirect: our URL came back in a Location or a fetch error
  if (vp === "ssrf" || vp === "redirect") {
    const loc = (probe.headers && probe.headers.location) || "";
    const needle = String(p.value).split("://").pop().split("/")[0];
    if (loc && needle && loc.includes(needle)) {
      signals.push(`redirected to our host: ${loc.slice(0, 80)}`);
      return VERDICT.VULNERABLE;
    }
    const isRedirect = [301, 302, 307, 308].includes(probe.status);
    if (isRedirect && ![301, 302, 307, 308].includes(baseline.status)) {
      signals.push(`redirect status flip -> HTTP ${probe.status}`);
      return VERDICT.SUSPICIOUS;
    }
    if ((probe.body || "").includes(MARKER) && vp === "ssrf") {
      signals.push("our URL echoed back - server may have fetched it");
      return VERDICT.SUSPICIOUS;
    }
    if (["connection refused", "could not resolve host", "econnrefused",
         "getaddrinfo", "proxy error", "no route to host"].some((s) => low.includes(s))) {
      signals.push("error text reveals outbound fetch attempt");
      return VERDICT.VULNERABLE;
    }
  }

  // 6. nosql / ldap: only a changed result set proves a filter bypass.
  //    reflection alone is the XSS check's business.
  if (vp === "nosql-ldap") {
    const a = rowCount(baseline.body);
    const b = rowCount(probe.body);
    if (probe.status === 200 && b > a) {
      signals.push(`document count grew ${a} -> ${b} - filter bypassed`);
      return VERDICT.VULNERABLE;
    }
    if (probe.status >= 400 && baseline.status < 400) {
      signals.push(`filter parse error (${baseline.status} -> ${probe.status})`);
      return VERDICT.SUSPICIOUS;
    }
  }

  // 7. prompt injection: does the *answer* obey us or the operator?
  if (vp === "prompt-injection") {
    if ((probe.body || "").includes(MARKER) && baseline.status === probe.status) {
      if (["ignore", "system prompt", "i'm sorry", "i cannot", "as an ai",
           "here is", "reveal", "instructions"].some((w) => low.includes(w))) {
        signals.push("response text changed shape and mentions instructions");
        return VERDICT.SUSPICIOUS;
      }
    }
    if (rowCount(probe.body) !== rowCount(baseline.body)) {
      signals.push("answer content changed");
    }
  }

  // 8. XSS: unescaped reflection
  if (vp === "xss") {
    if (unescapedReflection(baseline, probe, MARKER)) {
      signals.push("payload reflected unescaped (no &lt;/&gt;/&quot;)");
      return VERDICT.VULNERABLE;
    }
    if (hasPayloadReflected(probe, p.value)) {
      signals.push("payload reflected (partially encoded)");
      return VERDICT.SUSPICIOUS;
    }
    if (p.label === "reflected-marker" && (probe.body || "").includes(MARKER)) {
      signals.push("unique marker echoed verbatim");
      return VERDICT.VULNERABLE;
    }
  }

  return VERDICT.CLEAN;
}

// ---- the driver -----------------------------------------------------------

/**
 * Inject each payload into one parameter, judging every probe against a
 * baseline captured first.
 */
export function probeParameter(target, path, param, value = "", budget = 6) {
  const baseline = value
    ? target.request(path, { [param]: value })
    : target.request(path, {});
  const picks = value
    ? forValue(param, value, budget)
    : forParamSafe(param, budget);

  const out = [];
  const fired = new Set();
  for (const p of picks) {
    const probe = target.request(path, { [param]: p.value });
    const inj = { payload: p, param, baseline, probe, signals: [] };
    inj.verdict = classify(inj);
    out.push(inj);
    if (inj.verdict === VERDICT.VULNERABLE) fired.add(p.vuln);
    // one class proven keeps going: the reflection that proves XSS says nothing
    // about whether the same parameter also injects SQL.
    if (fired.size >= 2) break;
  }
  return out;
}

// imported lazily to keep the module graph flat
import { forParam as forParamSafe } from "./payloads.js";

// ---- finding construction -------------------------------------------------

const META = {
  xss: ["Reflected XSS", "high", "CWE-79",
    "Your input comes back into the page unescaped, so a crafted link can run script in a victim's session.",
    "HTML-encode output on the way out and add a strict CSP. Contextual escaping beats regex cleaning."],
  sqli: ["SQL injection", "critical", "CWE-89",
    "The database parsed our SQL and the result set changed. That is read and often write access to your entire database.",
    "Use parameterised queries / prepared statements everywhere. Never string-concatenate input into SQL. Least-privilege DB user."],
  cmdi: ["OS command injection", "critical", "CWE-78",
    "Input reached a shell and its output came back. This is remote code execution on your server.",
    "Never pass input to a shell. Use execve-style argument arrays with no shell, and validate against an allowlist."],
  ssti: ["Server-side template injection", "high", "CWE-1336",
    "The template engine evaluated our expression, so we control the server-side render context - often full RCE.",
    "Render with a logic-less template engine, or sandbox the one you use. Never evaluate user input as template source."],
  traversal: ["Path traversal / local file inclusion", "critical", "CWE-22",
    "Our encoded traversal reached a file outside the intended directory.",
    "Resolve the path, then verify it is inside an allowlisted root before opening it. Reject .. and encoded variants."],
  ssrf: ["Server-side request forgery", "high", "CWE-918",
    "The server fetched (or tried to fetch) a URL we supplied. From an internal service this reads cloud metadata and internal admin APIs.",
    "Allowlist outbound destinations, resolve-then-validate so DNS rebinding cannot point at 127.0.0.1, and block link-local ranges."],
  redirect: ["Open redirect", "low", "CWE-601",
    "The app redirects to an arbitrary external host. Perfect for phishing with a trusted-looking link.",
    "Allowlist redirect targets, or require relative paths only."],
  "nosql-ldap": ["NoSQL / LDAP injection", "high", "CWE-90",
    "A document or directory query accepted our operator, so filters can be bypassed or dumped.",
    "Type-check every field and escape LDAP filters."],
  "prompt-injection": ["Prompt injection", "high", "CWE-77",
    "The model followed instructions embedded in our input instead of the operator's rules.",
    "Treat model input as untrusted: separate instructions from data, require confirmation for tool calls, constrain the tool surface."],
};

export function toFinding(inj, url) {
  if (!inj || !["vulnerable", "suspicious"].includes(inj.verdict) || !inj.probe) return null;
  const p = inj.payload;
  const [baseTitle, baseSev, cwe, description, remediation] = META[p.vuln] || [
    "Injection detected", "high", "CWE-77", "", "Validate and encode output.",
  ];
  let title = `${baseTitle} via '${inj.param}' (${p.label})`;
  if (p.vuln === "xss" && p.label === "reflected-marker") {
    title = "Reflected input echoed without encoding (XSS risk) via '" + inj.param + "'";
  }
  const confidence = inj.verdict === "vulnerable" ? "high"
    : (inj.signals.length <= 1 ? "low" : "medium");
  const sev = inj.verdict === "vulnerable" ? baseSev : "medium";
  const probeBody = inj.probe.body || "";
  const idx = probeBody.indexOf(MARKER);
  const snippet = idx >= 0
    ? `...${probeBody.slice(Math.max(0, idx - 80), idx + 160).trim()}...`
    : (idx === -1 && p.value ? probeBody.slice(0, 200) : probeBody.slice(0, 200));

  return {
    title,
    severity: sev,
    cvssScore: cvssFor(p, sev),
    modality: p.vuln === "xss" ? "text" : "text",
    confidence,
    cwe,
    owasp: p.owasp,
    url,
    endpoint: url,
    parameter: inj.param,
    payload: p.value,
    description,
    remediation,
    evidence: {
      request: `GET ${url}?${inj.param}=${p.value}`,
      response_snippet: snippet,
      proof: inj.signals.join("; ") || "manual review recommended",
      extra: {
        verdict: inj.verdict,
        signals: inj.signals.slice(),
        baseline_status: inj.baseline.status,
        probe_status: inj.probe.status,
        baseline_len: (inj.baseline.body || "").length,
        probe_len: probeBody.length,
        payload_class: p.vuln,
        polyglot: p.polyglot,
      },
    },
    tags: ["active", p.vuln].concat(p.polyglot ? ["polyglot"] : ["single-context"]),
  };
}

// severity band -> a representative CVSS base score for the card
const BAND_SCORE = { critical: 9.1, high: 7.1, medium: 5.4, low: 3.1, info: 0.0 };

function cvssFor(p, sev) {
  // the payload carries its own vector in the catalogue; use it when we can
  if (p.cvss && typeof p.cvss.score === "number") return p.cvss.score;
  return BAND_SCORE[sev] ?? 0;
}

export { escapeHtml };