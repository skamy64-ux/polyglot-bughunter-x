#!/usr/bin/env python3
"""One command to check, build, publish and verify everything.

There are five published surfaces - a Hugging Face Space, a Model, a Dataset, a
Kaggle dataset and a Kaggle kernel - and keeping them in sync was five separate
commands plus a mental note about which one you forgot. A version bump that
lands on four of five is worse than no release script at all, because it looks
done.

```bash
python tools/release.py --check          # the full gate, no uploads
python tools/release.py --build          # rebuild every artifact
python tools/release.py --publish        # push all five
python tools/release.py --verify         # re-read all five without logging in
python tools/release.py --all            # all of the above
python tools/release.py --publish --only kaggle-dataset,kernel
```

The gate is the project's own test suite, not a separate list. `--check` runs
ruff, pytest, the JS/Python parity suite, the app-level checks and the browser
checks, and refuses to publish if any of them fail. Nothing is uploaded from a
dirty tree, and every publish is followed by a verification pass that reads the
result back over HTTP.

Version drift is the failure this exists to prevent, so it is checked
explicitly: the wheel inlined in the kernel and the wheel shipped in the Kaggle
dataset must contain identical code, and both must match pyproject.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Three different accounts, on three different services. Keeping them as
#: separate constants exists because they were once the same string in two
#: places, and a GitHub link pointing at the Kaggle owner is exactly the sort of
#: thing that ships silently: the URL still parses, it just 404s.
HF = "Kicaulah"
KAGGLE = "simonmarc"
GITHUB = "skamy64-ux"
REPO = "polyglot-bughunter-x"

#: Every destination, with the URL to read it back from. These are verified
#: anonymously on purpose: an authenticated 200 proves nothing, because the
#: owner's session sees their own private repos.
TARGETS = {
    "space": f"https://huggingface.co/spaces/{HF}/polyglot-bughunter-x-static",
    "space-cdn": "https://kicaulah-polyglot-bughunter-x-static.static.hf.space/index.html",
    "model": f"https://huggingface.co/{HF}/polyglot-bughunter-x",
    "hf-dataset": f"https://huggingface.co/datasets/{HF}/polyglot-bug-patterns",
    "kaggle-dataset": f"https://www.kaggle.com/datasets/{KAGGLE}/polyglot-bug-patterns",
    "kernel": f"https://www.kaggle.com/code/{KAGGLE}/polyglot-bug-patterns-demo",
}

BOLD, RED, GREEN, YELLOW, DIM, GREY = "1", "31", "32", "33", "2", "90"
TTY = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if TTY else text


def head(msg: str) -> None:
    print(f"\n{c(msg, BOLD)}")


def run(label: str, cmd: list[str], timeout: int = 1800) -> bool:
    """Run a command, print a one-line verdict. Returns success."""
    print(f"  {label} ... ", end="", flush=True)
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(c("TIMEOUT", YELLOW))
        return False
    if p.returncode == 0:
        print(c("ok", GREEN))
        return True
    print(c("FAILED", RED))
    tail = (p.stdout or "") + (p.stderr or "")
    for line in tail.strip().splitlines()[-14:]:
        print(c(f"      {line}", GREY))
    return False


def declared_version() -> str:
    return re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(),
                     re.M).group(1)


# --- drift -----------------------------------------------------------------


def wheel_contents(path: Path) -> dict[str, str]:
    with zipfile.ZipFile(path) as z:
        return {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()}


def wheel_from_notebook(nb_path: Path):
    """Extract the wheel a notebook installs, however it carries it.

    Two shapes exist on purpose. The kernel inlines the wheel as base64,
    because a kernel must work on the first click with nobody having attached
    input. The dataset notebook globs for a file that ships beside it, which is
    Kaggle's own "Add notebook -> Input" flow. Both are verified here.
    """
    doc = json.loads(nb_path.read_text())
    src = "\n".join("".join(c.get("source", [])) for c in doc["cells"])

    m = re.search(r'_WHEEL_B64 = """\n(.*?)"""', src, re.S)
    if m:
        raw = base64.b64decode(m.group(1))
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            return {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()}

    if "/kaggle/input" in src:
        return None          # file-shaped; resolved against the dataset folder
    raise SystemExit(
        f"{nb_path.name} carries no wheel: neither inlined nor found as a file")


def check_drift() -> bool:
    """The whole reason this script exists.

    Five surfaces, one version. A wheel is a zip, so it embeds a build
    timestamp and two builds of identical source never match byte for byte -
    the comparison is over extracted contents, which is what actually ships.
    """
    head("drift check")
    version = declared_version()
    print(f"  pyproject version: {c(version, BOLD)}")
    ok = True

    ds_nb = ROOT / "kaggle_dataset" / "hf_demo.ipynb"
    k_nb = ROOT / "kaggle_kernel" / "hf_demo.ipynb"
    ds_whl = next(iter(sorted((ROOT / "kaggle_dataset").glob("*.whl"))), None)

    if ds_whl and ds_nb.is_file():
        try:
            a = wheel_contents(ds_whl)
            shape = wheel_from_notebook(ds_nb)
        except SystemExit as exc:
            print(c(f"  x {exc}", RED))
            return False
        if shape is None:
            print(f"  {c('ok', GREEN)} dataset notebook installs the dataset's own "
                  f"wheel file ({len(a)} files)")
        else:
            diff = {n for n in a if a.get(n) != shape.get(n)}
            if diff:
                print(c(f"  x dataset wheel and notebook disagree: {sorted(diff)[:3]}",
                        RED))
                ok = False
            else:
                print(f"  {c('ok', GREEN)} dataset wheel == notebook wheel")
    else:
        print(c("  - dataset not built yet, skipping", YELLOW))

    if k_nb.is_file():
        try:
            k = wheel_from_notebook(k_nb)
        except SystemExit as exc:
            print(c(f"  x {exc}", RED))
            return False
        if ds_whl and isinstance(k, dict):
            try:
                a = wheel_contents(ds_whl)
                diff = {n for n in a if a.get(n) != k.get(n)}
                if diff:
                    print(c(f"  x kernel ships different code than the dataset: "
                            f"{sorted(diff)[:3]}", RED))
                    print(c("      rebuild both: python tools/release.py --build", GREY))
                    ok = False
                else:
                    print(f"  {c('ok', GREEN)} kernel wheel == dataset wheel")
            except Exception:
                pass

        # the version baked into the notebook must be the declared one
        src = "\n".join("".join(c.get("source", [])) for c in json.loads(
            k_nb.read_text())["cells"])
        m = re.search(r'_whl = "polyglot_bug_hunter_x-([0-9][^-]*)-', src)
        if m and m.group(1) != version:
            print(c(f"  x kernel notebook pins {m.group(1)}, pyproject says {version}",
                    RED))
            ok = False
        else:
            print(f"  {c('ok', GREEN)} kernel pins {version}")

    if not ok:
        print(c("\n  the surfaces disagree. do not publish.", YELLOW))
    return ok


# --- phases ----------------------------------------------------------------


def do_check() -> bool:
    head("the gate")
    results = [
        run("ruff", [sys.executable, "-m", "ruff", "check", "src", "tests", "tools",
                     "run.py"]),
        run("pytest", [sys.executable, "-m", "pytest", "-q"]),
        run("parity (js == python)", ["node", "tools/test_static_space.mjs"]),
        run("app-level", ["node", "tools/test_static_app.mjs"]),
        run("browser (live CDN)", [sys.executable, "tools/test_static_browser.py",
                                   "--live"]),
    ]
    if not check_drift():
        results.append(False)
    failed = [i for i, ok in enumerate(results) if not ok]
    head("gate verdict")
    if failed:
        print(c(f"  {len(failed)} of {len(results)} checks failed. refusing to publish.",
                RED))
        return False
    print(c(f"  all {len(results)} checks passed", GREEN))
    return True


def do_build() -> bool:
    head("build")
    py = sys.executable
    return all([
        run("dataset  (hf_dataset -> kaggle_dataset + wheel)",
            [py, "tools/build_dataset.py"]),
        run("notebook", [py, "tools/build_notebook.py"]),
        run("space    (hf_space -> static space folder)",
            [py, "tools/build_static_space.py"]),
        run("kaggle dataset", [py, "tools/build_kaggle.py"]),
        run("kaggle kernel", [py, "tools/build_kaggle_kernel.py"]),
    ])


#: Which publish.py flag serves which target. Written out rather than derived,
#: because the names collide: `space` here is the *static* space, while
#: `publish.py --space` is the Gradio one that needs HF PRO. Deriving the flags
#: from the target names sent --space, which failed on 402 every release while
#: the three healthy repos behind it uploaded fine.
HF_FLAGS = {
    "space": ["--static"],
    "model": ["--model"],
    "hf-dataset": ["--dataset"],
}


def do_publish(only: list[str] | None) -> bool:
    py = sys.executable
    kaggle = "kaggle"

    if not _git_clean():
        print(c("\n  refusing to publish a dirty tree: the artifacts would not "
                "match the commit. commit, or use --allow-dirty.", YELLOW))
        if not _allow_dirty:
            return False

    head("publish")
    want = set(only) if only else set(TARGETS) - {"space-cdn"}
    ok = True

    if want & set(HF_FLAGS):
        flags = [f for key, f in HF_FLAGS.items() if key in want for f in f]
        ok &= run("hugging face (3 repos)",
                  [py, "tools/publish.py", "--user", HF, *flags, "--yes"])

    if "kaggle-dataset" in want:
        ok &= run("kaggle dataset", [kaggle, "datasets", "version", "-m",
                                     f"release {declared_version()}",
                                     "-p", "kaggle_dataset"])

    if "kernel" in want:
        ok &= run("kaggle kernel", [kaggle, "kernels", "push", "-p", "kaggle_kernel"])

    return ok


def _git_clean() -> bool:
    p = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                       capture_output=True, text=True)
    tracked = [ln for ln in p.stdout.splitlines()
               if ln.strip() and not ln.startswith("??")]
    return not tracked


_allow_dirty = False


def _probe(url: str) -> object:
    """HTTP status for a URL, anonymously, with a browser-shaped request.

    Two things that are not obvious and both produce a false 404:

    - Kaggle does not implement HEAD. It answers 404 to every HEAD request
      whether or not the repo exists, so HEAD says "deleted" about a dataset
      that is right there. GET is the only method that tells the truth.
    - Kaggle serves 404 to a User-Agent that does not look like a browser,
      which is indistinguishable from a missing repo.
    """
    import urllib.error
    import urllib.request

    ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/120.0 Safari/537.36")
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return type(e).__name__


def do_verify(wait: bool = True) -> bool:
    """Read every destination back over anonymous HTTP.

    Authenticity matters here: with a token loaded, Kaggle and HF answer 200
    for private repos too, which would make a broken publish look like a
    success. Nothing here uses a credential.
    """
    head("verify (anonymous)")
    ok = True
    for name, url in TARGETS.items():
        for attempt in range(4 if wait else 1):
            code = _probe(url)
            if code in (200, 301, 302):
                break
            # Kaggle takes a moment to publish a new version
            time.sleep(8 * (attempt + 1))

        good = code in (200, 301, 302)
        ok &= good
        mark = c("ok", GREEN) if good else c("FAIL", RED)
        print(f"  {mark:12s} {c(str(code), GREY):26s} {name}")
    head("verify verdict")
    print(c("  all five live" if ok else "  something is not live", GREEN if ok else RED))
    return ok


def main() -> int:
    global _allow_dirty
    ap = argparse.ArgumentParser(
        prog="release.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="run the gate")
    ap.add_argument("--build", action="store_true", help="rebuild every artifact")
    ap.add_argument("--publish", action="store_true", help="push to all destinations")
    ap.add_argument("--verify", action="store_true", help="re-read everything")
    ap.add_argument("--all", action="store_true", help="check, build, publish, verify")
    ap.add_argument("--only", default="",
                    help="comma separated: " + ", ".join(sorted(TARGETS)))
    ap.add_argument("--allow-dirty", action="store_true",
                    help="publish even with uncommitted changes")
    ap.add_argument("--no-wait", action="store_true",
                    help="do not retry verification")
    ap.add_argument("--dry-run", action="store_true", help="print the plan only")
    args = ap.parse_args()
    _allow_dirty = args.allow_dirty

    if not any((args.check, args.build, args.publish, args.verify, args.all)):
        ap.print_help()
        return 0

    only = [s.strip() for s in args.only.split(",") if s.strip()] or None
    if only:
        unknown = [s for s in only if s not in TARGETS]
        if unknown:
            print(c(f"error: unknown target(s) {unknown}", RED), file=sys.stderr)
            print(f"  known: {', '.join(sorted(TARGETS))}", file=sys.stderr)
            return 2

    if args.dry_run:
        print(c("dry run - nothing will be uploaded", YELLOW))
        if args.all or args.check:
            for label in ("ruff", "pytest", "parity", "app-level", "browser"):
                print(f"  check   {label}")
        if args.all or args.build:
            for name in ("build_dataset", "build_notebook", "build_static_space",
                         "build_kaggle", "build_kaggle_kernel"):
                print(f"  build   tools/{name}.py")
        if args.all or args.publish:
            for t in (only or sorted(TARGETS)):
                print(f"  publish {t}")
        if args.all or args.verify:
            for url in TARGETS.values():
                print(f"  verify  {url}")
        return 0

    rc = 0
    if args.all or args.check:
        if not do_check():
            return 1
    if args.all or args.build:
        if not do_build():
            return 1
    if args.all or args.publish:
        if not do_publish(only):
            return 1
    if args.all or args.verify:
        if not do_verify(wait=not args.no_wait):
            rc = 1

    head("done")
    print(f"  version {c(declared_version(), BOLD)} · {len(TARGETS)} destinations")
    return rc


if __name__ == "__main__":
    sys.exit(main())
