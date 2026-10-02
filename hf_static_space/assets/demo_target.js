// GENERATED FILE - do not edit.
// Produced by tools/build_static_space.py from the Python source of truth.
// Edit src/polyglot_bug_hunter/ or locales/, then re-run the generator.

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
