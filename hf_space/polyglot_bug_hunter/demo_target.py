"""An intentionally vulnerable app that we host ourselves.

This is the whole virality trick: the "🚀 Scan Example" button in the Space
doesn't need httpbin.org, doesn't need a VPN, doesn't need the internet, and
can never accidentally get us emailed by an angry sysadmin. We boot this on
127.0.0.1 inside the Space container, scan it, and hand the visitor a real
report with real findings in about two seconds.

Every flaw here is deliberate and documented. Nothing in this file is reusable
as an attack: it reflects a fixed marker, and it never executes SQL or shell.
It is a target, not a weapon.
"""

from __future__ import annotations

import html
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

BANNER = (
    "PBHX-DEMO v1.0 - intentionally vulnerable, bound to 127.0.0.1 only. "
    "Do not deploy this. Do not copy the patterns into production."
)

MARKER = "PBHX7"
INVENTORY = [f"widget-{i}" for i in range(1, 6)]
PRODUCT_COLUMNS = 2      # sku, stock
# "fake" customer records - obviously fake, but shaped like real ones so the
# IDOR detector has something realistic to notice.
CUSTOMERS = {
    "1": {"name": "Alice Example", "email": "alice@example.invalid", "plan": "free"},
    "2": {"name": "Bob Example", "email": "bob@example.invalid", "plan": "pro"},
    "3": {"name": "Carla Example", "email": "carla@example.invalid", "plan": "enterprise"},
}


def _simulate_query(pid: str) -> tuple[str, list[str], str]:
    """Pretend to run `SELECT sku, stock FROM products WHERE id = '<pid>'`.

    Not a SQL parser - a *faithful enough* one to reproduce the four answers a
    real injectable app gives, because those four answers are exactly what a
    scanner needs to tell injection from reflection:

      ('rows', [...], note)   the query parsed and returned rows
      ('all',  [...], note)   a tautology matched every row
      ('none', [],   note)   parsed fine, matched nothing
      ('error', [],  msg)    the driver blew up (this is the golden signal)
    """
    q = "'" + pid + "'"
    # strip comments, the way a real lexer would before counting quotes
    stripped = re.sub(r"--[^\n]*", "", q)
    stripped = re.sub(r"/\*.*?\*/", "", stripped, flags=re.S)
    low = stripped.lower()

    # 1. unterminated string literal -> syntax error
    if low.count("'") % 2 == 1:
        return ("error", [],
                "You have an error in your SQL syntax; check the manual that "
                "corresponds to your MySQL server version for the right syntax to "
                f"use near '{html.escape(stripped[:40])}' at line 1 "
                "(psycopg2.errors.SyntaxError: unterminated quoted string)")

    # 2. ORDER BY past the end of the column list
    m = re.search(r"order\s+by\s+(\d+)", low)
    if m and int(m.group(1)) > PRODUCT_COLUMNS:
        return ("error", [],
                f"Unknown column '{m.group(1)}' in 'order clause' "
                "(pymysql.err.ProgrammingError: 1054)")

    # 3. UNION with the wrong number of columns
    if "union" in low:
        if "select" not in low:
            return ("error", [], "You have an error in your SQL syntax near 'UNION'")
        # count columns in our SELECT list
        tail = low.split("select", 1)[1].split("--")[0]
        cols = len([c for c in re.split(r",(?![^(]*\))", tail) if c.strip()])
        if cols != PRODUCT_COLUMNS:
            return ("error", [],
                    f"Column count doesn't match value count at row 1 "
                    f"(sqlalchemy.exc.ProgrammingError: {cols} != {PRODUCT_COLUMNS})")
        return ("all", INVENTORY, "UNION matched the whole table")

    # 4. tautology: OR <something always true>
    if re.search(r"(\bor\b)\s*(?:'?1'?=?'?1'?|true\b|1'\s*=\s*'1)", low):
        return ("all", INVENTORY, "tautology matched every row")

    # 5. parsed fine. Did it match a row?
    inner = stripped.strip().strip("'").strip()
    if re.fullmatch(r"-?\d+", inner):
        n = int(inner)
        return ("rows", [INVENTORY[(n + i) % len(INVENTORY)] for i in range(3)],
                f"WHERE id = '{inner}'")
    return ("none", [], f"WHERE id = '{inner}' -> no rows")


class DemoHandler(BaseHTTPRequestHandler):
    """Every handler here is a bug on purpose. The comments say which bug."""

    server_version = "pbhx-demo/1.0"
    sys_version = ""

    # -- plumbing ----------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:  # silence stderr spam
        pass

    def _send(self, body: str, status: int = 200,
              ctype: str = "text/html; charset=utf-8",
              extra_headers: dict[str, str] | None = None) -> None:
        raw = body.encode("utf-8", "replace")
        self.send_response(status)          # status line first, always
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        # BUG 1 (A05): no CSP, no HSTS, no nosniff, no X-Frame-Options.
        # BUG 2 (CWE-1004/614/1275): the session cookie below is missing
        # HttpOnly, Secure and SameSite - exactly like every real session cookie
        # somebody forgot about.
        self.send_header("Set-Cookie", self.BUGGY_COOKIE)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    #: BUG 2 (CWE-1004/614/1275): no HttpOnly, no Secure, no SameSite.
    BUGGY_COOKIE = "session=demo-not-a-real-session; Path=/"

    def _cookie(self) -> dict[str, str]:
        """Placeholder kept for symmetry; _send() always sets the cookie."""
        return {}

    # -- routes ------------------------------------------------------------

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path
        q = parse_qs(parts.query)

        if path == "/":
            return self._index(q)
        if path == "/search":
            return self._search(q)
        if path == "/customer":
            return self._customer(q)
        if path == "/product":
            return self._product(q)
        if path == "/profile":
            return self._profile(q)
        if path == "/redirect":
            return self._redirect(q)
        if path == "/render":
            return self._render(q)
        if path == "/status":
            return self._send_json({"ok": True, "note": "BUG: no auth check on this API"})
        if path == "/.env":
            # BUG 3 (CWE-538): exposed secrets file. Values are fake.
            return self._send("DEBUG=True\nSECRET_KEY=not-a-real-key\n"
                              "DB_URL=postgres://demo:demo@localhost/demo\n", 200,
                              "text/plain; charset=utf-8")
        if path == "/robots.txt":
            return self._send("User-agent: *\nDisallow: /internal/\n", 200,
                              "text/plain; charset=utf-8")
        if path.startswith("/static/js/"):
            return self._send("// demo js\n", 200, "application/javascript")
        return self._send("<h1>404</h1>", 404)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = parse_qs(raw)
        path = urlsplit(self.path).path
        cookie = self._cookie()

        if path == "/login":
            return self._login(form, cookie)
        if path == "/comment":
            return self._comment(form, cookie)
        if path == "/transfer":
            return self._transfer(form, cookie)
        if path == "/upload":
            return self._upload(raw, cookie)
        return self._send("<h1>404</h1>", 404)

    # -- handlers ----------------------------------------------------------

    def _send_json(self, obj: object, status: int = 200,
                   headers: dict[str, str] | None = None) -> None:
        import json
        self._send(json.dumps(obj), status, "application/json", headers)

    def _shell(self, body: str) -> str:
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="generator" content="pbhx-demo/1.0 WordPress 6.4.2">
<title>PBHX Demo Target</title>
<style>body{{font:16px system-ui;max-width:780px;margin:2rem auto;padding:0 1rem}}
nav a{{margin-right:1rem}}code{{background:#eee;padding:.1rem .3rem}}
.alert{{background:#fee;border:1px solid #c00;padding:.6rem;border-radius:6px}}
.out{{background:#f6f6f6;padding:.6rem;border-radius:6px;white-space:pre-wrap}}</style>
</head><body>
<div class="alert"><b>{BANNER}</b></div>
<nav><a href="/">home</a><a href="/search">search</a><a href="/customer?id=1">customer</a>
<a href="/product?id=1">product</a><a href="/profile?u=1">profile</a>
<a href="/redirect?next=/">redirect</a><a href="/render?tpl=hi">render</a></nav>
<hr>
{body}
<!-- TODO: remove demo token pbhx-demo-token-do-not-ship -->
</body></html>"""

    def _index(self, q: dict) -> None:
        # BUG 4 (CWE-79): reflected search term, no encoding at all.
        term = (q.get("q") or [""])[0]
        refl = term if term else ""
        self._send(self._shell(f"""
        <h1>PolyglotBugHunter-X demo target 🕷️</h1>
        <p>A deliberately broken little site so you can watch the hunter work.</p>
        <form method="GET" action="/search">
          <input type="text" name="q" value="{refl}" placeholder="search products">
          <button type="submit">Search</button>
        </form>
        <form method="POST" action="/login" class="login">
          <input type="text" name="user" placeholder="username">
          <input type="password" name="pass" placeholder="password">
          <button type="submit">Sign in</button>
        </form>
        <form method="POST" action="/comment">
          <input type="text" name="user" placeholder="your name">
          <textarea name="body" placeholder="say something"></textarea>
          <button type="submit">Post comment</button>
        </form>
        <h2>Endpoints</h2>
        <ul>
          <li><code>/search?q=</code> — reflected XSS</li>
          <li><code>/customer?id=</code> — IDOR, no auth</li>
          <li><code>/product?id=</code> — SQL injection</li>
          <li><code>/profile?u=</code> — command injection, reflected</li>
          <li><code>/redirect?next=</code> — open redirect</li>
          <li><code>/render?tpl=</code> — SSTI (Jinja-ish)</li>
          <li><code>/login</code> (POST) — no CSRF token, no lockout</li>
          <li><code>/comment</code> (POST) — stored XSS, no CSRF token, weak cookie</li>
          <li><code>/transfer</code> (POST) — no CSRF token, no auth</li>
          <li><code>/upload</code> (POST) — accepts any bytes as "audio"</li>
          <li><code>/.env</code> — exposed secrets</li>
        </ul>"""))

    def _search(self, q: dict) -> None:
        # BUG: reflected without escaping + a vulnerable response header (CRLF).
        term = (q.get("q") or [""])[0]
        hits = [w for w in INVENTORY if term.lower() in w.lower()]
        self._send(self._shell(f"""
        <h2>Search results for: {term}</h2>
        <p class="out">You searched: {term}</p>
        <ul>{''.join(f'<li>{h}</li>' for h in hits) or '<li>nothing</li>'}</ul>
        <p><a href="/search?q={term}">same again</a></p>"""))

    def _customer(self, q: dict) -> None:
        # BUG 5 (CWE-639): any id returns any customer, no session check.
        cid = (q.get("id") or ["1"])[0]
        c = CUSTOMERS.get(cid)
        if not c:
            return self._send(self._shell("<h2>No such customer</h2>"), 404)
        # BUG (CORS): reflects any Origin, allows credentials.
        origin = self.headers.get("Origin", "")
        headers = {}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        self._send(self._shell(f"""
        <h2>Customer #{cid}</h2>
        <dl>
          <dt>name</dt><dd>{html.escape(c['name'])}</dd>
          <dt>email</dt><dd>{html.escape(c['email'])}</dd>
          <dt>plan</dt><dd>{html.escape(c['plan'])}</dd>
          <dt>internal_id</dt><dd>{cid}</dd>
        </dl>"""), 200, "text/html; charset=utf-8", headers)

    def _product(self, q: dict) -> None:
        # BUG 6 (CWE-89): the id is pasted straight into a query string a database
        # driver would run. _simulate_query() reproduces the responses a real
        # injectable app gives: rows, all rows (tautology), no rows, or a 500 with
        # driver error text.
        pid = (q.get("id") or ["1"])[0]
        outcome, rows, note = _simulate_query(pid)

        if outcome == "error":
            self._send(self._shell(f"""
            <h2>Product #{html.escape(pid)}</h2>
            <p class="alert">{html.escape(note)}</p>"""), 500)
            return

        body = f"""
        <h2>Product #{html.escape(pid)}</h2>
        <table><tr><th>sku</th><th>stock</th></tr>
        {"" if not rows else "".join(f"<tr><td>{r}</td><td>{10 + i * 7}</td></tr>"
                                     for i, r in enumerate(rows))}
        </table>
        <p class="out">query: SELECT sku, stock FROM products {html.escape(note)}</p>"""
        self._send(self._shell(body))

    def _profile(self, q: dict) -> None:
        # BUG 7 (CWE-78): a shell call. We never run it - we only echo the
        # "output" for known harmless probes, which is exactly what a real
        # vulnerable page does with ;id
        u = (q.get("u") or ["1"])[0]
        out = ""
        low = u.lower()
        if MARKER.lower() in low or any(c in low for c in (";", "|", "$(")):
            if "id" in low:
                out = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
            elif "whoami" in low:
                out = "www-data"
            else:
                out = f"{u}"
        body = f"""
        <h2>Profile lookup</h2>
        <pre class="out">$ lookup-user {u}
{html.escape(out)}</pre>
        <p class="alert">BUG: this string reached a shell. The demo only echoes.</p>"""
        self._send(self._shell(body))

    def _redirect(self, q: dict) -> None:
        # BUG 8 (CWE-601): redirect anywhere.
        nxt = (q.get("next") or ["/"])[0]
        self.send_response(302)
        self.send_header("Location", nxt)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _render(self, q: dict) -> None:
        # BUG 9 (CWE-1336): a toy template engine that evaluates {{ ... }}.
        tpl = (q.get("tpl") or ["hello {{ name }}"])[0]
        rendered = _toy_template(tpl)
        self._send(self._shell(f"""
        <h2>Template render</h2>
        <p class="out">{rendered}</p>
        <p class="out">source: {tpl}</p>"""))

    def _login(self, form: dict, cookie: dict[str, str] | None = None) -> None:
        # BUG 10 (CWE-352): no CSRF token, no rate limit, no lockout.
        user = (form.get("user") or [""])[0]
        pwd = (form.get("pass") or [""])[0]
        self._send(self._shell(f"""
        <h2>Login</h2>
        <p class="out">attempt user={user} pass={'*' * len(pwd)}</p>
        <p class="alert">No CSRF token. No lockout. This is a demo.</p>"""),
                  extra_headers=cookie)

    def _comment(self, form: dict, cookie: dict[str, str] | None = None) -> None:
        # BUG 11 (CWE-79): stored XSS - stored in memory, reflected to everyone.
        body = (form.get("body") or [""])[0]
        with _LOCK:
            _COMMENTS.append((form.get("user", ["anon"])[0], body))
        self._send(self._shell(f"""
        <h2>Post a comment</h2>
        <form method="POST" action="/comment">
          <input type="text" name="user" placeholder="name">
          <textarea name="body">{html.escape(body)}</textarea>
          <button>Post</button>
        </form>
        <h3>Comments</h3>
        {_comment_list()}"""), extra_headers=cookie)

    def _transfer(self, form: dict, cookie: dict[str, str] | None = None) -> None:
        # BUG 12 (CWE-362 + CWE-352): no auth, no CSRF token, no idempotency
        # key, and a read-modify-write on the balance with a visible sleep.
        with _LOCK:
            _BALANCES.append(form.get("to", ["?"])[0])
            n = len(_BALANCES)
        self._send(self._shell(f"""
        <h2>Transfer done</h2>
        <p class="out">transfers processed: {n}</p>
        <p class="alert">BUG: no auth, no CSRF token, no idempotency key.</p>"""),
                  extra_headers=cookie)

    def _upload(self, raw: str, cookie: dict[str, str] | None = None) -> None:
        # BUG 13 (CWE-434): accepts any bytes, trusts the filename.
        name = "upload.bin"
        if "filename=" in raw:
            name = raw.split("filename=")[1].split("\r\n")[0].strip('"')
        with _LOCK:
            _UPLOADS.append((name, len(raw)))
        self._send_json({"stored": name, "declared": "audio/wav", "bytes": len(raw),
                         "note": "BUG: content-type never verified"}, headers=cookie)


_COMMENTS: list[tuple[str, str]] = []
_BALANCES: list[str] = []
_UPLOADS: list[tuple[str, int]] = []
_LOCK = threading.Lock()


def _comment_list() -> str:
    with _LOCK:
        # BUG: rendered raw on purpose, that's the stored XSS
        return "".join(f"<div class='comment'><b>{u}</b>: {b}</div>"
                       for u, b in _COMMENTS[-10:]) or "<p>none yet</p>"


def _toy_template(tpl: str) -> str:
    """Deliberately naive {{ expr }} evaluation, for {{7*7}} -> 49."""
    import re
    out = tpl
    for _ in range(3):                       # allow nested braces, then stop
        def ev(m: re.Match) -> str:
            expr = m.group(1).strip()
            if not re.fullmatch(r"[\d\s+\-*/()]+", expr):
                return m.group(0)
            try:
                return str(eval(expr, {"__builtins__": {}}, {}))
            except Exception:
                return m.group(0)
        out = re.sub(r"\{\{\s*([^}]+?)\s*\}\}", ev, out)
    return html.escape(out)


class DemoServer:
    """Context-managed demo target. `with DemoServer() as url: scan(url)`."""

    def __init__(self, port: int = 0) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), DemoHandler)
        self.port = self.httpd.server_address[1]
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def __enter__(self) -> DemoServer:
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        time.sleep(0.05)
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass


def serve(port: int = 8787) -> None:
    """Run it standalone: `python -m polyglot_bug_hunter.demo_target 8787`."""
    with DemoServer(port) as srv:
        print(f"{BANNER}\nserving on {srv.url}  (ctrl-c to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nbye")


if __name__ == "__main__":
    import sys
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8787)
