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
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 401 from huggingface.co means "private or does not exist". HF deliberately does
# not 404 a missing Space, so a 401 is a broken link.
URL_RE = re.compile(r"https?://[^\s)\"'<>\]]+")

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
        for raw in URL_RE.findall(p.read_text(encoding="utf-8", errors="replace")):
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
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "pbhx-linkcheck/1.0"})
    except ValueError as exc:
        return 0, f"unparseable: {exc}"
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, ""
    except urllib.error.HTTPError as e:
        return e.code, ""
    except urllib.error.URLError as e:
        return 0, str(e.reason)[:60]
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"[:60]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--timeout", type=int, default=12)
    args = ap.parse_args()

    found = collect()
    all_urls = sorted({u for urls in found.values() for u in urls})
    print(f"== link check: {len(all_urls)} unique URLs across {len(found)} files ==\n")

    bad = 0
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
        if not ok:
            bad += 1
        flag = "ok  " if ok else "BAD "
        print(f"  {flag} [{code or '--':>3}] {url}")
        if note:
            print(f"            {note}")
        if not ok:
            print(f"            referenced by: {', '.join(where)}")

    print()
    if bad:
        print(f"{bad} broken link(s).")
        return 1
    print("all links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())