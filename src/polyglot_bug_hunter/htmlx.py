"""HTML intelligence. stdlib HTMLParser, no BeautifulSoup, no lxml, no drama.

We need five things out of a page: links to follow, forms to poke, inputs to
fill, scripts to audit, and a DOM to screenshot. This gets all five in one
parse because crawling a target repeatedly is rude.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urldefrag, urljoin, urlsplit

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}

# attributes that make a URL interesting enough to probe
INTERESTING_PARAMS = (
    "q", "query", "search", "id", "page", "file", "path", "url", "redirect",
    "next", "return", "user", "name", "email", "msg", "message", "comment",
    "cat", "category", "lang", "sort", "order", "item", "product", "doc",
    "view", "template", "include", "content", "data", "ref", "token", "code",
    "host", "domain", "site", "feed", "src", "source", "dest", "target",
    "callback", "continue", "goto", "out", "viewstate", "state", "cmd",
)


@dataclass(slots=True)
class Form:
    action: str
    method: str = "GET"
    id: str = ""
    classes: str = ""
    fields: list[dict] = field(default_factory=list)
    enctype: str = ""

    @property
    def is_search(self) -> bool:
        blob = f"{self.action} {self.id} {self.classes}".lower()
        return any(k in blob for k in ("search", "query", "find", "q="))

    @property
    def is_login(self) -> bool:
        blob = f"{self.action} {self.id}".lower()
        pw = [f for f in self.fields if f.get("type") == "password"]
        return bool(pw) or any(k in blob for k in ("login", "signin", "sign-in", "auth"))

    def to_dict(self) -> dict:
        return {
            "action": self.action, "method": self.method, "id": self.id,
            "classes": self.classes, "enctype": self.enctype,
            "fields": self.fields, "is_login": self.is_login, "is_search": self.is_search,
        }


class PageParser(HTMLParser):
    """Single pass: links, forms, inputs, scripts, images, comments, sinks."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.links: list[str] = []
        self.forms: list[Form] = []
        self.scripts: list[dict] = []
        self.images: list[dict] = []
        self.comments: list[str] = []
        self.meta: dict[str, str] = {}
        self.inline_js: list[str] = []
        self.lang = ""
        self.title = ""
        self._form: Form | None = None
        self._script: dict | None = None
        self._in_title = False
        self._skip = 0

    # -- helpers -----------------------------------------------------------

    def _abs(self, href: str) -> str:
        return urldefrag(urljoin(self.base, (href or "").strip()))[0]

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {(k or "").lower(): (v if v is not None else "") for k, v in attrs}

    # -- parser callbacks --------------------------------------------------

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = self._attrs(attrs)
        if tag == "html":
            self.lang = a.get("lang", "")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            if a.get("name"):
                self.meta[a["name"].lower()] = a.get("content", "")
            elif a.get("http-equiv", "").lower() == "refresh":
                self.meta["refresh"] = a.get("content", "")
        elif tag == "a" and a.get("href"):
            self.links.append(self._abs(a["href"]))
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower()
            if "stylesheet" in rel or "preload" in rel:
                self.meta.setdefault("assets", "")
                self.meta["assets"] = (self.meta["assets"] + " " + self._abs(a["href"])).strip()
        elif tag == "form":
            self._form = Form(action=self._abs(a.get("action", "") or self.base),
                              method=(a.get("method", "GET") or "GET").upper(),
                              id=a.get("id", ""), classes=a.get("class", ""),
                              enctype=a.get("enctype", ""))
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form.fields.append({
                "tag": tag,
                "name": a.get("name", "") or a.get("id", ""),
                "type": (a.get("type", "text") or "text").lower(),
                "value": a.get("value", ""),
                "placeholder": a.get("placeholder", ""),
                "required": "required" in a,
                "maxlength": a.get("maxlength", ""),
                "accept": a.get("accept", ""),
            })
        elif tag == "script":
            self._script = {"src": self._abs(a["src"]) if a.get("src") else "",
                            "inline": not a.get("src"), "body": "", "nonce": "nonce" in a}
        elif tag == "img":
            self.images.append({
                "src": self._abs(a.get("src", "")),
                "alt": a.get("alt", ""),
                "onerror": a.get("onerror", ""),
                "width": a.get("width", ""), "height": a.get("height", ""),
            })
        elif tag in ("button", "iframe", "object", "embed", "video", "audio", "source"):
            self.meta.setdefault("rich", "")
            self.meta["rich"] = (self.meta["rich"] + f" {tag}").strip()
        if tag in VOID and self._script is None:
            pass

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._form is not None:
            if any(f.get("name") for f in self._form.fields):
                self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._script is not None:
            self.scripts.append(self._script)
            self._script = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._script is not None and not self._script["src"]:
            self._script["body"] += data
            if len(self._script["body"]) < 400_000:
                self.inline_js.append(data)

    def handle_comment(self, data: str) -> None:
        text = (data or "").strip()
        if text:
            self.comments.append(text[:500])

    def handle_startendtag(self, tag: str, attrs: list) -> None:
        self.handle_starttag(tag, attrs)


# --- analysis on top of a parse --------------------------------------------


def interesting_params(url: str) -> dict[str, str]:
    """Query params worth injecting into, with their current values."""
    qs = parse_qs(urlsplit(url).query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in qs.items() if k}


def rank_params(params: dict[str, str]) -> list[tuple[str, str]]:
    """User-controlled-looking params first, boring ones last."""
    def score(item: tuple[str, str]) -> tuple[int, str]:
        name = item[0].lower()
        hot = any(name == k or k in name for k in INTERESTING_PARAMS)
        return (0 if hot else 1, name)

    return sorted(params.items(), key=score)


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def crawlable(links: list[str], base: str, same_origin_only: bool = True,
              limit: int = 15) -> list[str]:
    """Dedupe, filter, prefer interesting paths, drop static noise."""
    seen: list[str] = []
    skip_ext = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".css",
                ".js", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".pdf", ".zip",
                ".map", ".xml.gz")
    for link in links:
        link = link.strip()
        if not link.startswith(("http://", "https://")) or link in seen:
            continue
        if link.split("?")[0].lower().endswith(skip_ext):
            continue
        if len(link) > 500:
            continue
        if same_origin_only and not same_origin(link, base):
            continue
        seen.append(link)
        if len(seen) >= limit:
            break
    # a parametrised URL is a juicier target than a bare one
    return sorted(seen, key=lambda u: (0 if "?" in u else 1, len(u)))


def extract_forms(html: str, base_url: str) -> list[Form]:
    p = PageParser(base_url)
    p.feed(html or "")
    return p.forms


# --- DOM XSS sinks ----------------------------------------------------------

# Where untrusted data lands in a browser and turns into code. This is the
# static half of DOM-XSS detection: we can't run a browser on a free CPU Space,
# but we CAN read the code and see if it assigns location/URL text to a sink.
SINKS = [
    (r"\b(?:document\.write|document\.writeln)\s*\(", "document.write", "critical"),
    (r"\.(?:innerHTML|outerHTML)\s*=\s*[^=]", "innerHTML/outerHTML", "high"),
    (r"\beval\s*\(", "eval()", "critical"),
    (r"\bnew\s+Function\s*\(", "new Function()", "high"),
    (r"\bsetTimeout\s*\(\s*['\"]", "setTimeout(string)", "high"),
    (r"\bsetInterval\s*\(\s*['\"]", "setInterval(string)", "high"),
    (r"\blocation\s*=\s*[^=]", "location assignment", "high"),
    (r"\blocation\.(?:hash|search|href)\s*", "location source", "medium"),
    (r"\bpostMessage\s*\(", "postMessage", "medium"),
    (r"\bsrcdoc\s*=", "iframe srcdoc", "high"),
    (r"\bimport\s*\(", "dynamic import()", "medium"),
    (r"\bexecScript\s*\(", "execScript", "high"),
    (r"insertAdjacentHTML\s*\(", "insertAdjacentHTML", "high"),
]

# Where the data comes from. If a source feeds a sink without sanitising, boom.
SOURCES = re.compile(
    r"(location\.(?:hash|search|href|pathname)|document\.URL|document\.documentURI|"
    r"document\.referrer|window\.name|document\.cookie|localStorage|sessionStorage|"
    r"postMessage|URLSearchParams|getParameterByName|__proto__|baseURI)", re.I)

SANITIZERS = re.compile(
    r"(DOMPurify|sanitize(?:HTML|Url|Dom)?\s*\(|escapeHtml|encodeURIComponent|"
    r"textContent\s*=|innerText\s*=|he\s*\(|bleach\.clean|createSafeHtml|"
    r"xss\s*\(|filterXSS|validator\.escape)", re.I)


@dataclass(slots=True)
class DomIssue:
    sink: str
    severity: str
    snippet: str
    source: str = ""
    sanitized: bool = False


def audit_inline_js(js: str) -> list[DomIssue]:
    """Find source -> sink flows in inline scripts and inline event handlers."""
    issues: list[DomIssue] = []
    for pattern, name, sev in SINKS:
        for m in re.finditer(pattern, js or ""):
            start = max(0, m.start() - 200)
            ctx = js[start: m.end() + 200]
            if SANITIZERS.search(ctx):
                continue
            src = SOURCES.search(ctx)
            issues.append(DomIssue(
                sink=name, severity=sev,
                snippet=re.sub(r"\s+", " ", ctx).strip()[:260],
                source=src.group(0) if src else "",
            ))
            break  # one example per sink is enough evidence
    return issues


def audit_handlers(parser: PageParser, html: str) -> list[DomIssue]:
    """on* attributes are JS too, and they're where 'safe' sites still die."""
    out: list[DomIssue] = []
    for attr, val in re.findall(r"\b(on[a-z]+)\s*=\s*\"([^\"]{1,400})\"", html or "", re.I):
        low = val.lower()
        if any(k in low for k in ("location", "document.cookie", "document.url",
                                  "referrer", "postmessage", "eval", "fetch(")):
            if not SANITIZERS.search(val):
                out.append(DomIssue(
                    sink=f"inline {attr}",
                    severity="high" if any(k in low for k in ("location", "cookie", "eval"))
                             else "medium",
                    snippet=re.sub(r"\s+", " ", val).strip()[:260],
                    source=next((s for s in ("location", "document.cookie", "referrer",
                                             "postMessage", "eval", "fetch(")
                                 if s.lower() in low), ""),
                ))
    return out


def audit_comments(parser: PageParser) -> list[str]:
    """Comments are free recon: todo/fixme/dev hosts/passwords show up here."""
    findings = []
    pat = re.compile(r"(todo|fixme|hack|xxx|password|passwd|secret|api[_-]?key|"
                     r"token|internal|staging|dev\.|localhost|admin)", re.I)
    for c in parser.comments:
        if pat.search(c):
            findings.append(c)
    return findings
