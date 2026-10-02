#!/usr/bin/env python3
"""Build the Static Space (free, no PRO, no server).

The JavaScript is a *port* of the Python, not a rewrite. So every data table -
the 12 locales, the 43 payloads, the vocabulary - is generated straight from the
Python source of truth here, which means the two can never drift. Only the logic
that has no Python equivalent (canvas PNG, Web Audio WAV, DOM wiring) is
hand-written.

    python tools/build_static_space.py

Layout produced:

    hf_static_space/
      index.html          <- no build step, no npm, served as-is
      assets/*.js|css     <- data modules generated, logic modules hand-written
      data/*.json         <- copy of the dataset, so it is browsable in the repo

Then validate that the port matches the original:

    node tools/test_static_space.mjs
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from polyglot_bug_hunter import payloads as P  # noqa: E402
from polyglot_bug_hunter.i18n import FLAGS, NATIVE_NAMES, RTL, SUPPORTED  # noqa: E402
from polyglot_bug_hunter.models import Cvss  # noqa: E402

OUT = ROOT / "hf_static_space"
ASSETS = OUT / "assets"

BANNER = (
    "// GENERATED FILE - do not edit.\n"
    "// Produced by tools/build_static_space.py from the Python source of truth.\n"
    "// Edit src/polyglot_bug_hunter/ or locales/, then re-run the generator.\n"
)


def emit_i18n() -> int:
    """All 12 locales as one JS module, with English as the embedded fallback."""
    tables = {}
    for code in SUPPORTED:
        raw = json.loads((ROOT / "locales" / f"{code}.json").read_text(encoding="utf-8"))
        tables[code] = {k: v for k, v in raw.items() if not k.startswith("_meta")}
    en = json.loads((ROOT / "locales" / "en.json").read_text(encoding="utf-8"))
    meta = {
        code: {
            "name": NATIVE_NAMES[code],
            "flag": FLAGS[code],
            "dir": "rtl" if code in RTL else "ltr",
        }
        for code in SUPPORTED
    }

    body = [
        BANNER,
        "// PolyglotBugHunter-X - i18n. Flattened keys keep the JSON readable.",
        "",
        "const SUPPORTED = %s;" % json.dumps(SUPPORTED),
        "const META = %s;" % json.dumps(meta, ensure_ascii=False, indent=2),
        "",
        "// embedded so the UI renders even if a fetch is blocked",
        "const FALLBACK = %s;" % json.dumps(
            {k: v for k, v in en.items() if not k.startswith("_meta")},
            ensure_ascii=False, indent=2),
        "",
        "const TABLES = %s;" % json.dumps(tables, ensure_ascii=False, indent=2),
        "",
        _I18N_JS,
    ]
    (ASSETS / "i18n.js").write_text("\n".join(body), encoding="utf-8")
    return sum(len(t) for t in tables.values())


_I18N_JS = r"""
const ALIASES = {
  "zh-cn": "zh", "zh-tw": "zh", "zh-hans": "zh", "zh-hant": "zh",
  "pt-br": "pt", "en-us": "en", "en-gb": "en", "in": "id", "iw": "he",
};

export function normalize(tag) {
  if (!tag) return "en";
  let t = String(tag).trim().replace(/_/g, "-").toLowerCase();
  if (t === "auto" || t === "browser" || t === "default") return detect();
  t = ALIASES[t] || t;
  const base = t.split("-")[0];
  const out = ALIASES[base] || base;
  return SUPPORTED.includes(out) ? out : (SUPPORTED.includes(out.slice(0, 2)) ? out.slice(0, 2) : "en");
}

export function detect(...candidates) {
  for (const c of candidates) {
    if (!c) continue;
    const tag = normalize(String(c));
    if (tag !== "en" || String(c).toLowerCase().startsWith("en")) return tag;
  }
  if (typeof navigator !== "undefined" && navigator.language) return normalize(navigator.language);
  return "en";
}

export class Translator {
  constructor(code = "en") {
    this.code = normalize(code);
    this.table = TABLES[this.code] || {};
  }
  get(key, fmt = {}) {
    let v = this.table[key];
    if (v === undefined) v = FALLBACK[key];
    if (v === undefined) {
      // same last-resort as the python Translator: title-cased words, never a
      // raw snake_case key in someone's face
      return String(key).replace(/[_.]/g, " ").trim()
        .replace(/\b\w/g, (c) => c.toUpperCase());
    }
    return String(v).replace(/\{(\w+)\}/g, (m, name) =>
      Object.prototype.hasOwnProperty.call(fmt, name) ? String(fmt[name]) : m);
  }
  severity(k) { return this.get(`severity.${k}`); }
  status(k) { return this.get(`status.${k}`); }
  cls(k, fallback = k) {
    const v = this.table[`class.${k}`] ?? FALLBACK[`class.${k}`];
    return v === undefined ? fallback : v;
  }
  isRtl() { return (META[this.code]?.dir || "ltr") === "rtl"; }
  flag() { return META[this.code]?.flag || "🌐"; }
  label() { const m = META[this.code]; return m ? `${m.flag} ${m.name}` : this.code; }
  options() { return SUPPORTED.map((c) => [META[c].label, c]); }
}

export { SUPPORTED, META };
"""


def emit_payloads() -> tuple[int, int]:
    """The payload catalogue plus the parameter-name router, in JS."""
    rows = []
    for cls, p in P.iter_all():
        av, ac, pr, ui, scope, c, i, a = p.cvss
        cvs = Cvss.build(av=av, ac=ac, pr=pr, ui=ui, scope=scope,
                         conf=c, integ=i, avail=a)
        rows.append({
            "id": P.fingerprint(p),
            "bucket": cls,
            "vuln": p.vuln,
            "label": p.label,
            "value": p.value,
            "polyglot": p.polyglot,
            "note": p.note,
            "cwe": p.cwe,
            "owasp": p.owasp,
            "confidence": p.confidence,
            "cvss": {"vector": cvs.vector, "score": cvs.score,
                     "severity": cvs.severity.value},
        })

    routes = [
        {"group": g, "keywords": list(k), "bucket": b, "count": n}
        for g, k, b, n in P.ROUTES
    ]
    stats = P.stats()

    body = [
        BANNER,
        "// PolyglotBugHunter-X - payload catalogue. Ported from payloads.py.",
        "",
        "export const MARKER = %s;" % json.dumps(P.MARKER),
        "export const STATS = %s;" % json.dumps(stats, indent=2),
        "export const ROUTES = %s;" % json.dumps(routes, indent=2),
        "export const UNIVERSAL_XSS = %d;" % P.UNIVERSAL_XSS,
        "export const UNIVERSAL_SSTI = %d;" % P.UNIVERSAL_SSTI,
        "",
        "export const PAYLOADS = %s;" % json.dumps(rows, ensure_ascii=False, indent=2),
        "",
        "export const BUCKETS = PAYLOADS.reduce((acc, p) => {",
        "  (acc[p.bucket] ||= []).push(p);",
        "  return acc;",
        "}, {});",
        "",
        "export const ALL = PAYLOADS;",
        "",
        _PAYLOAD_JS,
    ]
    (ASSETS / "payloads.js").write_text("\n".join(body), encoding="utf-8")
    return len(rows), stats["polyglot"]


_PAYLOAD_JS = r"""
const SSTI_ARITH = ["template-arith", "el-arith", "erb-arith"];

const sstiArith = () => BUCKETS.xss.filter((p) => SSTI_ARITH.includes(p.label));

export function forParam(name, budget = 6) {
  const raw = (name || "").trim();
  const whole = raw.toLowerCase();
  const tokens = new Set(
    raw.toLowerCase().replace(/-/g, "_").split("_").filter(Boolean));
  tokens.add(whole);

  let picks = [];
  for (const route of ROUTES) {
    if (route.keywords.some((k) => tokens.has(k) || whole.includes(k))) {
      picks = picks.concat((BUCKETS[route.bucket] || []).slice(0, route.count));
    }
  }
  picks = picks.concat((BUCKETS.xss || []).slice(0, UNIVERSAL_XSS));
  picks = picks.concat(sstiArith().slice(0, UNIVERSAL_SSTI));

  let out = [];
  const seen = new Set();
  for (const p of picks) {
    if (!seen.has(p.value)) { seen.add(p.value); out.push(p); }
  }
  if (!out.length) {
    out = (BUCKETS.xss || []).slice(0, UNIVERSAL_XSS)
      .concat(sstiArith().slice(0, UNIVERSAL_SSTI));
  }
  if (out.length < budget) {
    for (const p of [...(BUCKETS.sqli || []).slice(0, 2),
                     ...(BUCKETS["prompt-injection"] || []).slice(0, 1),
                     ...(BUCKETS.ssrf || []).slice(0, 1)]) {
      if (out.length >= budget) break;
      if (!out.some((q) => q.value === p.value)) out.push(p);
    }
  }
  return out.slice(0, budget);
}

export function forValue(name, value, budget = 6) {
  let picks = forParam(name, budget + 4);
  const v = (value || "").trim().toLowerCase();
  if (/^(https?|ftp):\/\//.test(v) || (v.includes("//") && v.includes(".") && !v.includes(" "))) {
    picks = [...(BUCKETS.ssrf || []).slice(0, 3),
             ...(BUCKETS.redirect || []).slice(0, 2), ...picks];
  } else if (/^\d+$/.test(v)) {
    const labels = new Set(["order-by-probe", "union-null", "tautology-comment"]);
    picks = (BUCKETS.sqli || []).filter((p) => labels.has(p.label)).concat(picks);
  } else if (v.includes("@")) {
    picks = (BUCKETS.sqli || []).slice(1, 3).concat(picks);
  }
  const seen = new Set();
  const out = [];
  for (const p of picks) {
    if (!seen.has(p.value)) { seen.add(p.value); out.push(p); }
  }
  return out.slice(0, budget);
}

export function polyglots() { return ALL.filter((p) => p.polyglot); }
export function byVuln(v) { return ALL.filter((p) => p.vuln === v); }
"""


def emit_cvss() -> None:
    """CVSS v3.1 base scoring. Validated against the Python original in node."""
    (ASSETS / "cvss.js").write_text(BANNER + _CVSS_JS, encoding="utf-8")


_CVSS_JS = r"""
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
"""


def emit_demo_target() -> None:
    """The simulated vulnerable app, mirroring demo_target.py's behaviour."""
    (ASSETS / "demo_target.js").write_text(BANNER + _DEMO_JS, encoding="utf-8")


_DEMO_JS = r"""
// The bundled demo target, reimplemented for the browser.
//
// There is no HTTP server in a Static Space, so `request()` is a faithful port of
// demo_target.py's routing and of _simulate_query(). It reproduces the exact
// responses a real injectable app gives, because those responses are what the
// detectors need in order to tell injection from reflection.
//
// It simulates. It never executes SQL or a shell - see BUG notes below.

export const MARKER = "PBHX7";
export const INVENTORY = ["widget-1", "widget-2", "widget-3", "widget-4", "widget-5"];
export const PRODUCT_COLUMNS = 2;

const CUSTOMERS = {
  1: { name: "Alice Example", email: "alice@example.invalid", plan: "free" },
  2: { name: "Bob Example", email: "bob@example.invalid", plan: "pro" },
  3: { name: "Carla Example", email: "carla@example.invalid", plan: "enterprise" },
};

export const BUGS = {
  1: "reflected XSS on /search?q",
  2: "IDOR on /customer?id",
  3: "SQL injection on /product?id",
  4: "command injection on /profile?u",
  5: "open redirect on /redirect?next",
  6: "SSTI on /render?tpl",
  7: "stored XSS on /comment",
  8: "no CSRF token on /login and /comment",
  9: "session cookie without HttpOnly/Secure/SameSite",
  10: "no CSP, HSTS, nosniff or X-Frame-Options",
  11: "debug and error text leaked in responses",
  12: "comments leak an internal token",
  13: "/.env served without authentication",
  14: "/upload accepts any bytes as audio",
  15: "/transfer has no auth, no CSRF, no idempotency key",
};

// ---- the SQL simulator, ported line for line from _simulate_query ---------

export function simulateQuery(pid) {
  const q = `'${pid}'`;
  const stripped = q.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");
  const low = stripped.toLowerCase();

  // 1. unterminated string literal -> syntax error
  const quotes = (low.match(/'/g) || []).length;
  if (quotes % 2 === 1) {
    return {
      outcome: "error",
      rows: [],
      note: `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${stripped.slice(0, 40)}' at line 1 (psycopg2.errors.SyntaxError: unterminated quoted string)`,
    };
  }

  // 2. ORDER BY past the end of the column list
  const ob = low.match(/order\s+by\s+(\d+)/);
  if (ob && Number(ob[1]) > PRODUCT_COLUMNS) {
    return {
      outcome: "error",
      rows: [],
      note: `Unknown column '${ob[1]}' in 'order clause' (pymysql.err.ProgrammingError: 1054)`,
    };
  }

  // 3. UNION with the wrong number of columns
  if (low.includes("union")) {
    if (!low.includes("select")) {
      return { outcome: "error", rows: [], note: "You have an error in your SQL syntax near 'UNION'" };
    }
    const tail = low.split("select")[1].split("--")[0];
    const cols = tail.split(/,(?![^(]*\))/).filter((c) => c.trim()).length;
    if (cols !== PRODUCT_COLUMNS) {
      return {
        outcome: "error",
        rows: [],
        note: `Column count doesn't match value count at row 1 (sqlalchemy.exc.ProgrammingError: ${cols} != ${PRODUCT_COLUMNS})`,
      };
    }
    return { outcome: "all", rows: INVENTORY, note: "UNION matched the whole table" };
  }

  // 4. tautology
  if (/(\bor\b)\s*(?:'?1'?=?'?1'?|true\b|1'\s*=\s*'1)/.test(low)) {
    return { outcome: "all", rows: INVENTORY, note: "tautology matched every row" };
  }

  // 5. parsed fine, did it match a row?
  const inner = stripped.trim().replace(/^'|'$/g, "").trim();
  if (/^-?\d+$/.test(inner)) {
    const n = Number(inner);
    // JS `%` keeps the sign of the dividend, Python's does not. -1 % 5 is -1 in
    // JS (-> undefined) and 4 in Python, so normalise explicitly.
    const wrap = (i) => ((i % INVENTORY.length) + INVENTORY.length) % INVENTORY.length;
    return {
      outcome: "rows",
      rows: [0, 1, 2].map((i) => INVENTORY[wrap(n + i)]),
      note: `WHERE id = '${inner}'`,
    };
  }
  return { outcome: "none", rows: [], note: `WHERE id = '${inner}' -> no rows` };
}

// ---- the toy template engine, ported from _toy_template ------------------

export function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" }[c]
  ));
}

export function toyTemplate(tpl) {
  let out = String(tpl);
  for (let pass = 0; pass < 3; pass += 1) {
    out = out.replace(/\{\{\s*([^}]+?)\s*\}\}/g, (m, expr) => {
      const e = expr.trim();
      if (!/^[\d\s+\-*/()]+$/.test(e)) return m;
      try {
        // arithmetic only: the charset check above is the sandbox
        const v = Function(`"use strict";return (${e});`)();  // eslint-disable-line no-new-func
        // python raises ZeroDivisionError on /0 and leaves the tag alone
        if (typeof v !== "number" || !Number.isFinite(v)) return m;
        return String(v);
      } catch {
        return m;
      }
    });
  }
  // the python version escapes on the way out; match it exactly
  return escapeHtml(out);
}

const BUGGY_COOKIE = "session=demo-not-a-real-session; Path=/";

let comments = [];
let transfers = 0;
let uploads = 0;

export function resetState() { comments = []; transfers = 0; uploads = 0; }

// ---- the router -----------------------------------------------------------

export function request(path, params = {}, method = "GET", body = null, headers = {}) {
  const p = { ...params };
  const q = new URLSearchParams(p).toString();
  const full = path + (q ? `?${q}` : "");

  // request headers are NOT response headers. Mixing them up makes a CORS probe
  // look like a CORS finding when the only thing that moved is our own header.
  const text = (s, status = 200, extra = null) => ({
    status, body: s, headers: {
      "content-type": "text/html; charset=utf-8",
      // BUG 9: no HttpOnly, no Secure, no SameSite
      "set-cookie": BUGGY_COOKIE,
      // BUG 10: no CSP, no HSTS, no nosniff, no X-Frame-Options
      ...(extra || {}),
    },
  });
  void headers;

  if (method === "POST") {
    if (path === "/login") {
      const user = body.user ?? "", pw = body.pass ?? "";
      return text(`<h2>Login</h2><p class="out">attempt user=${user} pass=${"*".repeat(pw.length)}</p>`
        + `<p class="alert">No CSRF token. No lockout. This is a demo.</p>`);
    }
    if (path === "/comment") {
      // BUG 7: stored, and reflected to everyone without escaping
      comments.push([body.user || "anon", body.body || ""]);
      return text(renderCommentPage(`<pre class="out">stored: ${escapeHtml(body.body || "")}</pre>`));
    }
    if (path === "/transfer") {
      // BUG 15: no auth, no CSRF token, no idempotency key
      transfers += 1;
      return text(`<h2>Transfer done</h2><p class="out">transfers processed: ${transfers}</p>`
        + `<p class="alert">BUG: no auth, no CSRF token, no idempotency key.</p>`);
    }
    if (path === "/upload") {
      // BUG 14: accepts any bytes, trusts the filename
      uploads += 1;
      return { status: 200, body: JSON.stringify({
        stored: "upload.bin", declared: "audio/wav", bytes: String(body?.bytes ?? 0),
        note: "BUG: content-type never verified",
      }), headers: { "content-type": "application/json", "set-cookie": BUGGY_COOKIE } };
    }
    return text("<h1>404</h1>", 404);
  }

  switch (path) {
    case "/":
      // the forms matter: the CSRF assessor reads them, exactly as it does in
      // the python original, so the port stays faithful
      return text(`<h1>PBHX demo target</h1><p>${Object.values(BUGS).length} deliberate bugs.</p>
<form method="GET" action="/search">
  <input type="text" name="q" value=""><button type="submit">Search</button>
</form>
<form method="POST" action="/login" class="login">
  <input type="text" name="user" value=""><input type="password" name="pass" value="">
  <button type="submit">Sign in</button>
</form>
<form method="POST" action="/comment">
  <input type="text" name="user" value=""><textarea name="body"></textarea>
  <button type="submit">Post comment</button>
</form>
<!-- TODO: remove demo token pbhx-demo-token-do-not-ship -->`);

    case "/search": {
      const term = p.q ?? "";
      // BUG 1: reflected without any encoding
      return text(`<h2>Search results for: ${term}</h2><p class="out">You searched: ${term}</p>`
        + `<ul>${INVENTORY.filter((w) => w.includes(term.toLowerCase()))
            .map((w) => `<li>${w}</li>`).join("") || "<li>nothing</li>"}</ul>`);
    }

    case "/customer": {
      const cid = String(p.id ?? "1");
      const c = CUSTOMERS[cid];
      if (!c) return text("<h2>No such customer</h2>", 404);
      // BUG 2: any id returns any customer, no session check.
      // BUG: CORS reflects any Origin and allows credentials.
      const origin = headers.Origin || "";
      const extra = origin
        ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" }
        : {};
      return text(`<h2>Customer #${escapeHtml(cid)}</h2><dl>`
        + `<dt>name</dt><dd>${escapeHtml(c.name)}</dd>`
        + `<dt>email</dt><dd>${escapeHtml(c.email)}</dd>`
        + `<dt>plan</dt><dd>${escapeHtml(c.plan)}</dd>`
        + `<dt>internal_id</dt><dd>${escapeHtml(cid)}</dd></dl>`, 200, extra);
    }

    case "/product": {
      const pid = String(p.id ?? "1");
      const sim = simulateQuery(pid);
      if (sim.outcome === "error") {
        // BUG 3 + BUG 11: the driver error text is rendered straight into the page
        return text(`<h2>Product #${escapeHtml(pid)}</h2>`
          + `<p class="alert">${escapeHtml(sim.note)}</p>`, 500);
      }
      const rows = sim.rows.length
        ? sim.rows.map((r, i) => `<tr><td>${r}</td><td>${10 + i * 7}</td></tr>`).join("")
        : "";
      return text(`<h2>Product #${escapeHtml(pid)}</h2>`
        + `<table><tr><th>sku</th><th>stock</th></tr>${rows}</table>`
        + `<p class="out">query: SELECT sku, stock FROM products ${escapeHtml(sim.note)}</p>`);
    }

    case "/profile": {
      const u = String(p.u ?? "1");
      const low = u.toLowerCase();
      // BUG 4: reaches a shell. This only *echoes* what the shell would print.
      let out = "";
      if (low.includes(MARKER.toLowerCase()) || [";", "|", "$("].some((c) => low.includes(c))) {
        out = low.includes("id") ? "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
          : low.includes("whoami") ? "www-data" : u;
      }
      return text(`<h2>Profile lookup</h2><pre class="out">$ lookup-user ${escapeHtml(u)}\n`
        + `${escapeHtml(out)}</pre><p class="alert">BUG: this string reached a shell. The demo only echoes.</p>`);
    }

    case "/redirect": {
      // BUG 5: redirects anywhere
      const next = String(p.next ?? "/");
      return { status: 302, body: "", headers: { location: next, "set-cookie": BUGGY_COOKIE } };
    }

    case "/render": {
      // BUG 6: naive {{ }} evaluation
      const tpl = String(p.tpl ?? "hello {{ name }}");
      return text(`<h2>Template render</h2><p class="out">${escapeHtml(toyTemplate(tpl))}</p>`
        + `<p class="out">source: ${escapeHtml(tpl)}</p>`);
    }

    case "/status":
      return { status: 200, body: JSON.stringify({ ok: true }),
        headers: { "content-type": "application/json" } };

    // BUG 13: exposed secrets file. Values are obviously fake.
    case "/.env":
      return { status: 200,
        body: "DEBUG=True\nSECRET_KEY=not-a-real-key\nDB_URL=postgres://demo:demo@localhost/demo\n",
        headers: { "content-type": "text/plain; charset=utf-8" } };

    case "/robots.txt":
      return { status: 200, body: "User-agent: *\nDisallow: /internal/\n",
        headers: { "content-type": "text/plain; charset=utf-8" } };

    default:
      return text("<h1>404</h1>", 404);
  }
}

export function renderCommentPage(extra = "") {
  // BUG 7: rendered raw, which is exactly what makes it stored XSS
  const list = comments.slice(-10)
    .map(([u, b]) => `<div class="comment"><b>${u}</b>: ${b}</div>`).join("")
    || "<p>none yet</p>";
  return `<h2>Post a comment</h2>${extra}<h3>Comments</h3>${list}`;
}

export function stateCounts() {
  return { comments: comments.length, transfers, uploads };
}
"""


def emit_vocab() -> None:
    vocab = json.loads((ROOT / "hf_model" / "payload_vocabulary.json")
                       .read_text(encoding="utf-8"))
    cfg = json.loads((ROOT / "hf_model" / "config.json").read_text(encoding="utf-8"))
    body = [
        BANNER,
        "// payload_vocabulary.json + config.json, for the About tab.",
        "export const VOCAB = %s;" % json.dumps(vocab, ensure_ascii=False, indent=2),
        "",
        "export const CONFIG = %s;" % json.dumps(cfg, ensure_ascii=False, indent=2),
        "",
    ]
    (ASSETS / "vocab.js").write_text("\n".join(body), encoding="utf-8")


def emit_package_json() -> None:
    """Marks the assets as ES modules for node (browsers already know, because
    index.html loads them with <script type="module">). HF Static Spaces serve the
    folder as-is and ignore this file."""
    (OUT / "package.json").write_text(json.dumps({
        "name": "polyglot-bug-hunter-x",
        "version": "1.0.0",
        "type": "module",
        "private": True,
        "description": "ES module marker so node can run the port test. "
                       "Browsers do not need this and HF does not use it.",
        "license": "MIT",
    }, indent=2) + "\n", encoding="utf-8")


def copy_dataset() -> int:
    data_out = OUT / "data"
    data_out.mkdir(parents=True, exist_ok=True)
    n = 0
    for f in sorted((ROOT / "hf_dataset" / "data").glob("*")):
        shutil.copy2(f, data_out / f.name)
        n += 1
    for name in ("hf_model/payload_vocabulary.json", "hf_model/scoring_profile.json"):
        src = ROOT / name
        if src.is_file():
            shutil.copy2(src, data_out / src.name)
            n += 1
    nb = ROOT / "notebooks" / "hf_demo.ipynb"
    if nb.is_file():
        shutil.copy2(nb, data_out / nb.name)
        n += 1
    return n


def main() -> int:
    ASSETS.mkdir(parents=True, exist_ok=True)

    keys = emit_i18n()
    count, poly = emit_payloads()
    emit_cvss()
    emit_demo_target()
    emit_vocab()
    emit_package_json()
    files = copy_dataset()

    print(f"static space assembled -> {OUT}")
    print(f"  i18n.js     {keys} translated keys across 12 locales")
    print(f"  payloads.js {count} payloads ({poly} polyglot) + router")
    print(f"  cvss.js     CVSS v3.1 base scoring")
    print(f"  demo_target.js  simulated vulnerable app")
    print(f"  vocab.js    config + vocabulary")
    print(f"  data/       {files} data files")
    print()
    print("  hand-write the remaining logic modules, then validate:")
    print("    node tools/test_static_space.mjs")
    return 0


if __name__ == "__main__":
    sys.exit(main())