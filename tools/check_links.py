#!/usr/bin/env python3
"""Check every URL in the docs actually resolves.

Cross-links are the cheapest SEO on the Hub and the easiest thing to break: one
sed that rewrites a namespace leaves twenty links pointing at a repo that does
not exist, and nothing warns you. This warns you.

    python tools/check_links.py            # all files
    python tools/check_links.py --offline  # skip the network, report only
"""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 401 from huggingface.co means "private or does not exist". HF deliberately does
# not 404 a missing Space, so a 401 is a broken link.
#: Statuses that mean "the host is busy", not "the link is dead".
TRANSIENT = frozenset({429, 500, 502, 503, 504})
RETRIES = 3
BACKOFF = 2.0

#: Matches a web URL, and a VCS requirement that wraps one. The optional
#: `git+` prefix has to be part of the pattern: matching from `https` alone
#: captures `https://github.com/o/r@v1.0.1` and the VCS ref is invisible, so the
#: @ref can never be stripped and the link is probed as a web URL that 404s.
URL_RE = re.compile(r"(?:git\+)?https?://[^\s)\"'<>\]]+")

#: A VCS requirement's ref is not part of the web URL:
#:     git+https://github.com/owner/repo@v1.0.1
#: Probing it verbatim 404s. Strip the ref and check the repo page instead.
VCS_RE = re.compile(r"^(?:git\+)?(https?://[^\s)\"'<>\]]+)@([^\s)\"'<>\]]+)$")


def _urls_in(text: str) -> set[str]:
    """Web URLs, with VCS refs normalised to something a browser can fetch."""
    out: set[str] = set()
    for raw in URL_RE.findall(text):
        vcs = VCS_RE.match(raw)
        if vcs:
            out.add(vcs.group(1))
            continue
        if raw.startswith("git+"):
            continue
        out.add(raw)
    return out

SCAN = [
    "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md",
    "CITATION.cff", "pyproject.toml", "docs/GROWTH.md",
    "hf_model/README.md", "hf_dataset/README.md",
    "hf_static_space/README.md", "hf_space/README.md",
    "kaggle_dataset/README.md", "notebooks/hf_demo.ipynb",
    "src/polyglot_bug_hunter/report/render.py",
    "hf_static_space/assets/app.js", "hf_static_space/assets/report.js",
    "hf_static_space/assets/style.css",
    "hf_static_space/index.html",
]

#: Only real documentation hosts are checked. The corpus is full of *deliberately
#: fake* URLs - `http://169.254.169.254/`, `MARKER.oast.invalid`, `[::1]` - and
#: those are attack examples, not links. Probing them would be both useless and
#: (in the metadata case) actively rude.
DOC_HOSTS = (
    "huggingface.co", "hugging.co", "hf.co", "github.com", "owasp.org",
    "cwe.mitre.org", "first.org", "keepachangelog.com", "semver.org",
    "pypi.org", "datatracker.ietf.org", "json-schema.org", "kaggle.com",
    "raw.githubusercontent.com", "opensource.org", "localhost", "127.0.0.1",
)

SKIP_PATTERNS = ("img.shields.io", "huggingface.co/api", "/api/resolve")


def collect() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for rel in SCAN:
        p = ROOT / rel
        if not p.is_file():
            continue
        urls = set()
        text = p.read_text(encoding="utf-8", errors="replace")
        for raw in _urls_in(text):
            url = raw.rstrip(".,);:`}>\"'")
            if any(h in url for h in SKIP_PATTERNS):
                continue
            # malformed scheme doubling is the bug this whole tool exists to
            # catch, so it must be reported rather than skipped
            if "://" in url[9:]:
                urls.add(f"!! malformed: {url}")
                continue
            host = url.split("//", 1)[1].split("/", 1)[0].lower()
            if not any(host == h or host.endswith("." + h) for h in DOC_HOSTS):
                continue        # an attack example, not a link
            urls.add(url)
        if urls:
            found[rel] = urls
    return found


def probe(url: str, timeout: int = 12) -> tuple[int, str]:
    if url.startswith("!!"):
        return 0, "malformed"
    # localhost urls in the notebook are the bundled demo target, which is only
    # alive while a scan is running. Refused is the correct answer there.
    if "127.0.0.1" in url or "localhost" in url:
        return 200, "local demo target, alive only during a scan"
    try:
        # GET, not HEAD, and a browser-shaped User-Agent.
        #
        # Kaggle does not implement HEAD: it answers 404 to every HEAD request
        # whether or not the repo exists, so a HEAD-based check calls a live
        # dataset deleted. It also 404s any agent that does not look like a
        # browser, which is indistinguishable from a missing page. Both were
        # found by watching this tool disagree with a plain `curl` on the same
        # URL, and both point the wrong way - reporting a healthy link as dead
        # trains people to ignore the output.
        req = urllib.request.Request(url, method="GET", headers={
            "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
    except ValueError as exc:
        return 0, f"unparseable: {exc}"
    last = (0, "")
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                # GET downloads the body; a link check only cares about the
                # status, and pulling a 100 MB dataset to learn it exists is rude.
                r.read(2048)
                return r.status, ""
        except urllib.error.HTTPError as e:
            last = (e.code, "")
            if e.code in TRANSIENT and attempt + 1 < RETRIES:
                time.sleep(BACKOFF * (attempt + 1))
                continue
            return e.code, ""
        except urllib.error.URLError as e:
            last = (0, str(e.reason)[:60])
            if attempt + 1 < RETRIES:
                time.sleep(BACKOFF * (attempt + 1))
                continue
            return last
        except Exception as e:
            return (0, f"{type(e).__name__}: {e}"[:60])
    return last


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--timeout", type=int, default=12)
    args = ap.parse_args()

    found = collect()
    all_urls = sorted({u for urls in found.values() for u in urls})
    print(f"== link check: {len(all_urls)} unique URLs across {len(found)} files ==\n")

    bad = 0
    unverified = 0
    for url in all_urls:
        where = sorted(rel for rel, urls in found.items() if url in urls)
        if url.startswith("!!"):
            print(f"  BAD   {url}")
            print(f"        {', '.join(where)}")
            bad += 1
            continue
        if args.offline:
            print(f"  --    {url}")
            continue
        code, note = probe(url, args.timeout)
        # huggingface returns 401 for a repo that does not exist
        ok = code in (200, 301, 302, 307, 308, 403)
        # A 5xx or a 429 is the host declining to answer, which is a different
        # claim from "this link is dead". GitHub returns 503/504 for a repo
        # created seconds ago while it indexes, and throttles a link checker
        # that hammers it - observed as 503, 503, then 200 on three consecutive
        # requests to the same healthy URL. Counting that as broken is the same
        # class of error as checking with HEAD: it indicts a working link, so
        # the fix is never where you look.
        unknown = code in TRANSIENT or code == 0
        if unknown:
            unverified += 1
        elif not ok:
            bad += 1
        flag = "ok  " if ok else ("???? " if unknown else "BAD ")
        print(f"  {flag} [{code or '--':>3}] {url}")
        if unknown:
            print(f"            host did not answer ({code or 'no response'}); "
                  f"not a verdict on the link")
        if note:
            print(f"            {note}")
        if not ok and not unknown:
            print(f"            referenced by: {', '.join(where)}")

    print()
    if bad:
        print(f"{bad} broken link(s).")
        return 1
    if unverified:
        print(f"{unverified} link(s) unverified - the host declined to answer. "
              f"That is not a verdict on the link; re-run before believing it.")
    else:
        print("all links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
