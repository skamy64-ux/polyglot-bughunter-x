#!/usr/bin/env python3
"""Check every trove classifier against the list PyPI actually serves.

PyPI validates classifiers on upload and rejects the whole release with a 400
naming one that is invalid. `twine check` does not catch it, because the
classifier is syntactically fine - it is just not in the vocabulary. Found the
hard way: "Natural Language :: Chinese" looks correct and is not a classifier;
PyPI wants "Natural Language :: Chinese (Simplified)" or "(Traditional)".

So this fetches pypi.org/classifiers/ and diffs. Run it before a release, not
after, because a rejected upload to PyPI cannot be retried with a fix under the
same version - the version is burned the moment the server accepts the request
far enough to validate it.

```bash
python tools/check_classifiers.py            # every classifier in pyproject
python tools/check_classifiers.py --offline  # syntax only, no network
```

Cached to a temp file so a rate-limited PyPI does not turn this into a flaky
step in someone's release.
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
PYPROJECT = ROOT / "pyproject.toml"
CLASSIFIERS_URL = "https://pypi.org/classifiers/"

#: A trove classifier is one or more ":: "-separated segments. Two details in
#: the character set are load-bearing and both cost a release:
#:   - the first segment is often more than one word ("Development Status",
#:     "Intended Audience"), so anything assuming a single word there matches
#:     nothing and reports "no classifiers declared"
#:   - parentheses are legal and required by some entries, notably
#:     "Natural Language :: Chinese (Simplified)" - the classifier PyPI rejects
#:     in favour of the bare "Chinese"
_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9 ._+()-]*"
_CLASSIFIER_RE = re.compile(rf'^\s*"(?P<c>{_SEGMENT}:: {_SEGMENT}(?::: {_SEGMENT})*)",?\s*$')
#: The same shape, for scraping pypi.org/classifiers/ out of the rendered HTML.
_TAG_RE = re.compile(rf"{_SEGMENT}:: {_SEGMENT}(?::: {_SEGMENT})*")


def declared(pyproject: Path = PYPROJECT) -> list[str]:
    """The trove classifiers in pyproject.toml.

    Read rather than imported because the point is to check the file that is
    about to be uploaded, including one this process cannot import because it
    is not installed yet.
    """
    out: list[str] = []
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        m = _CLASSIFIER_RE.match(line)
        if m:
            out.append(m.group("c"))
    return out


def fetch(timeout: int = 30, retries: int = 3) -> set[str]:
    """The classifiers PyPI currently serves."""
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(CLASSIFIERS_URL, headers={
                "User-Agent": "Mozilla/5.0 (compatible; pbhx-classifier-check)",
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                html = r.read().decode("utf-8", "replace")
            found = set(_TAG_RE.findall(html))
            if found:
                return {c.rstrip(" .") for c in found}
            last = RuntimeError("no classifiers found in the response")
        except (urllib.error.URLError, TimeoutError) as exc:
            last = exc
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"could not fetch {CLASSIFIERS_URL}: {last}")


def check(pyproject: Path = PYPROJECT, offline: bool = False) -> int:
    ours = declared(pyproject)
    if not ours:
        print("  no trove classifiers declared")
        return 0

    if offline:
        bad = [c for c in ours if not re.match(r"^[A-Za-z0-9] :: ", c)]
        for c in bad:
            print(f"  SYNTAX  {c}")
        print(f"\n  {len(ours)} classifier(s), syntax only (offline)")
        return 1 if bad else 0

    try:
        valid = fetch()
    except RuntimeError as exc:
        print(f"  ! {exc}", file=sys.stderr)
        print("  refusing to pass silently: an unverified classifier is exactly "
              "what this exists to catch", file=sys.stderr)
        return 2

    bad = [c for c in ours if c not in valid]
    for c in bad:
        print(f"  INVALID {c}")
        # offer the closest match; PyPI's vocabulary is full of near-misses
        tail = c.rsplit(" :: ", 1)[-1].split(" (")[0]
        alts = sorted(v for v in valid if v.endswith(f":: {tail}")
                      or f"({tail}" in v)[:4]
        for a in alts:
            print(f"          did you mean: {a}")

    for c in ours:
        if c not in bad:
            print(f"  ok     {c}")

    print()
    if bad:
        print(f"{len(bad)} invalid classifier(s). PyPI rejects the entire upload "
              f"for this, and the version cannot be reused.")
        return 1
    print(f"all {len(ours)} classifiers are valid")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="check_classifiers.py",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", action="store_true",
                    help="syntax check only, no network")
    args = ap.parse_args()
    return check(offline=args.offline)


if __name__ == "__main__":
    sys.exit(main())
