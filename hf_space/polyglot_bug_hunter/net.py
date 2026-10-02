"""Tiny HTTP client. urllib only, policy-gated, timing-aware.

Why not requests/httpx? Because the core has to import on a free CPU Space with
zero wheels, and because we need precise control over redirects, cookies and
per-request timing for the differential tests. `requests` gets used when it
happens to be installed (nicer TLS, connection pooling), but never required.
"""

from __future__ import annotations

import gzip
import http.cookiejar
import io
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from http.client import HTTPResponse

from .config import ScanConfig
from .safety import ScanPolicy

try:  # optional, nicer when present
    import requests  # type: ignore

    HAS_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    HAS_REQUESTS = False


@dataclass(slots=True)
class Response:
    url: str
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    method: str = "GET"
    request_body: str = ""
    error: str = ""
    redirects: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def content_type(self) -> str:
        return self.header("content-type", "").split(";")[0].strip().lower()

    @property
    def cookies(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for crumb in self.header("set-cookie").split(";"):
            if "=" in crumb:
                name, _, val = crumb.partition("=")
                if name.strip():
                    out[name.strip().lower()] = val.strip()
        return out

    @property
    def set_cookie_raw(self) -> list[str]:
        return [c for c in self.header("set-cookie").split("\n") if c.strip()]

    def snippet(self, needle: str, width: int = 160) -> str:
        """Return text around the first hit of `needle` - the money shot."""
        if not needle:
            return ""
        idx = self.body.find(needle)
        if idx < 0:
            return ""
        start = max(0, idx - width // 2)
        end = min(len(self.body), idx + len(needle) + width)
        return ("..." if start else "") + self.body[start:end].strip() + (
            "..." if end < len(self.body) else ""
        )

    def contains(self, *needles: str) -> bool:
        return any(n and n in self.body for n in needles)


class Http:
    """Policy-enforcing HTTP client. Every request goes through `.get/.post`."""

    def __init__(self, policy: ScanPolicy, config: ScanConfig | None = None) -> None:
        self.policy = policy
        self.cfg = config or ScanConfig()
        self.jar = http.cookiejar.CookieJar()
        self.log: list[tuple[str, str, int, float]] = []
        self._opener = self._build_opener()
        self._session = requests.Session() if HAS_REQUESTS else None
        if self._session:
            self._session.verify = self.cfg.verify_tls
            self._session.max_redirects = self.cfg.max_redirects

    # -- plumbing ----------------------------------------------------------

    def _build_opener(self) -> urllib.request.OpenerDirector:
        ctx = ssl.create_default_context()
        if not self.cfg.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx),
        ]

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            """Manual redirects so we can log and budget each hop."""

            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        handlers.append(NoRedirect)
        return urllib.request.build_opener(*handlers)

    def headers_for(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {
            "User-Agent": self.cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        }
        h.update(self.cfg.extra_headers)
        h.update(extra or {})
        return h

    # -- verbs -------------------------------------------------------------

    def get(self, url: str, **kw: object) -> Response:
        return self.request("GET", url, **kw)  # type: ignore[arg-type]

    def post(self, url: str, data: dict[str, str] | None = None, **kw: object) -> Response:
        return self.request("POST", url, data=data or {}, **kw)  # type: ignore[arg-type]

    def request(
        self,
        method: str,
        url: str,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Response:
        method = method.upper()
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)

        # both gates run before a single byte leaves the box
        self.policy.check_url(url)
        self.policy.check_method(method)
        self.policy.throttle()

        body_bytes = urllib.parse.urlencode(data).encode() if data else None
        resp = Response(url=url, method=method)
        start = time.perf_counter()

        try:
            raw = self._dispatch(method, url, body_bytes, headers or {}, timeout)
            self._fill(resp, raw)
        except urllib.error.HTTPError as exc:
            # 3xx and 4xx/5xx land here too - the body is not the only thing
            # that matters. Location and Set-Cookie drive open-redirect and
            # cookie findings, so keep the headers.
            resp.status = exc.code
            resp.reason = exc.reason or ""
            try:
                resp.headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
                resp.body = _decode(exc.read(),
                                    (exc.headers or {}).get("Content-Encoding", ""))
            except Exception:
                resp.headers = resp.headers or {}
            resp.error = "" if 300 <= exc.code < 400 else f"HTTPError {exc.code}"
        except urllib.error.URLError as exc:
            resp.error = f"URLError: {exc.reason}"
        except TimeoutError:
            resp.error = "timeout"
        except Exception as exc:  # never let one bad request kill the scan
            resp.error = f"{type(exc).__name__}: {exc}"
        finally:
            resp.elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            self.log.append((method, url, resp.status, resp.elapsed_ms))

        if resp.error and "HTTPError" not in resp.error and not resp.status:
            resp.status = 0
        return resp

    def _dispatch(self, method, url, body, headers, timeout):
        t = timeout or self.cfg.timeout
        if self._session is not None:
            kw: dict[str, object] = {"headers": headers, "timeout": t,
                                     "allow_redirects": False}
            if body:
                kw["data"] = body
            return self._session.request(method, url, **kw)

        req = urllib.request.Request(url, data=body, method=method)
        for k, v in self.headers_for(headers).items():
            req.add_header(k, v)
        if body:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        return self._opener.open(req, timeout=t)

    def _fill(self, resp: Response, raw) -> None:
        if isinstance(raw, requests.Response if HAS_REQUESTS else ()):
            resp.status = raw.status_code
            resp.reason = raw.reason or ""
            resp.headers = {k.lower(): v for k, v in raw.headers.items()}
            resp.body = raw.text or ""
            return
        if not isinstance(raw, HTTPResponse):
            return
        resp.status = raw.status
        resp.reason = raw.reason or ""
        resp.headers = {k.lower(): v for k, v in raw.getheaders()}
        resp.body = _decode(raw.read(), raw.headers.get("Content-Encoding", ""))

    # -- helpers -----------------------------------------------------------

    def fetch_following(self, url: str, limit: int | None = None) -> Response:
        """Follow redirects by hand, keeping the hop list for the report."""
        limit = limit if limit is not None else self.cfg.max_redirects
        seen: list[str] = []
        current = url
        resp = self.get(current)
        while resp.status in (301, 302, 303, 307, 308) and len(seen) < limit:
            loc = resp.header("location")
            if not loc:
                break
            current = urllib.parse.urljoin(current, loc)
            if current in seen:
                break
            seen.append(current)
            resp = self.get(current)
        resp.redirects = seen
        return resp

    def stats(self) -> dict[str, float | int]:
        times = [t for *_, t in self.log] or [0.0]
        return {
            "requests": len(self.log),
            "total_ms": round(sum(times), 1),
            "avg_ms": round(sum(times) / len(times), 1),
            "max_ms": round(max(times), 1),
        }


def replace_param(url: str, name: str, value: str) -> str:
    """Rebuild `url` so `name=value` appears exactly once, in its original spot.

    Appending to a URL that already carries the parameter produces
    `/x?id=1&id=2`, and most servers honour the *first* one - so the probe would
    look at the untouched original and every differential test would come back
    "clean". This is the single most important function in the scanner.
    """
    parts = urllib.parse.urlsplit(url)
    original = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)

    pairs: list[tuple[str, str]] = []
    replaced = False
    for key, val in original:
        if key != name:
            pairs.append((key, val))
        elif not replaced:          # first occurrence wins, later ones drop
            pairs.append((name, value))
            replaced = True
    if not replaced:
        pairs.append((name, value))

    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(pairs), parts.fragment))


def _decode(data: bytes, encoding: str = "") -> str:
    if not data:
        return ""
    encoding = (encoding or "").lower()
    try:
        if "gzip" in encoding:
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read()
        elif "deflate" in encoding:
            data = zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        pass
    for cs in ("utf-8", "latin-1"):
        try:
            return data.decode(cs)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


# --- small parsing helpers used across scanners ---------------------------

_META_RE = re.compile(r"<meta[^>]+>", re.I)
_ATTR_RE = re.compile(r"""([\w:-]+)\s*=\s*["']?([^"'>\s]+)""", re.I)


def meta_content(html: str, name: str) -> str:
    for tag in _META_RE.findall(html or ""):
        attrs = {k.lower(): v for k, v in _ATTR_RE.findall(tag)}
        if attrs.get("name", "").lower() == name.lower():
            return attrs.get("content", "")
    return ""


def page_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


def detect_tech(html: str, headers: dict[str, str] | None = None) -> list[str]:
    """Fingerprint from headers + markup. No external calls, no wappalyzer dep."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    html = html or ""
    tech: list[str] = []

    def add(name: str) -> None:
        if name not in tech:
            tech.append(name)

    if "x-powered-by" in h:
        add(h["x-powered-by"][:40])
    if h.get("server", "").lower().startswith(("nginx", "apache", "caddy", "cloudflare",
                                               "iis", "envoy", "litespeed")):
        add(h["server"].split("/")[0])
    if "cloudflare" in h.get("server", "").lower() or h.get("cf-ray"):
        add("Cloudflare")
    if "x-vercel" in h or "x-vercel-id" in h or "x-now" in h:
        add("Vercel")
    if "x-nf-request-id" in h:
        add("Netlify")
    if "x-amz-cf-id" in h or "x-amz-request-id" in h:
        add("AWS")
    if "x-github-request-id" in h:
        add("GitHub Pages")
    if "squarespace" in h.get("server", "").lower():
        add("Squarespace")

    cms = [
        ("wp-content", "WordPress"), ("wp-includes", "WordPress"),
        ("cdn.shopify.com", "Shopify"), ("/_next/static", "Next.js"),
        ("/static/js/main", "React"), ("data-reactroot", "React"),
        ("ng-version", "Angular"), ("__next_data__", "Next.js"),
        ("csrfmiddlewaretoken", "Django"), ("_method\"", "Ruby on Rails"),
        ("phpsessid", "PHP"), ("asp.net", "ASP.NET"), ("__viewstate", "ASP.NET"),
        ("laravel_session", "Laravel"), ("x-powered-by: php", "PHP"),
    ]
    blob = html[:200_000].lower() + " ".join(f"{k}:{v}" for k, v in h.items()).lower()
    for needle, name in cms:
        if needle in blob:
            add(name)
    if "google-analytics" in blob or "gtag(" in blob:
        add("Google Analytics")
    if "recaptcha" in blob:
        add("reCAPTCHA")
    return tech
