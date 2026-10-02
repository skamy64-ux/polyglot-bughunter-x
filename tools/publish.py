#!/usr/bin/env python3
"""Upload everything to Hugging Face: Space, Model, Dataset.

```bash
pip install -U huggingface_hub
huggingface-cli login            # or: hf auth login

python tools/publish.py --user YOUR_USERNAME            # dry run, prints the plan
python tools/publish.py --user YOUR_USERNAME --space    # do it
python tools/publish.py --user YOUR_USERNAME --all
```

The dry run is the default on purpose. `create_repo` is one-way for the repo
type and mostly one-way for the name, and you do not want to discover a typo
after uploading 40 files.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HF = ROOT / "hf_space"                 # gradio space, needs HF PRO
STATIC = ROOT / "hf_static_space"     # static space, free, this is the live one
MODEL = ROOT / "hf_model"
DATASET = ROOT / "hf_dataset"

REPOS = {
    # free tier, deployed, this is the one that shows up on your profile
    "static": {"path": STATIC, "type": "space", "name": "polyglot-bughunter-x-static",
               "extra_args": ["--space-sdk", "static"]},
    # requires an HF PRO subscription - create_repo returns 402 otherwise
    "space": {"path": HF, "type": "space", "name": "polyglot-bughunter-x",
              "extra_args": ["--space-sdk", "gradio"]},
    "model": {"path": MODEL, "type": "model", "name": "polyglot-bughunter-x",
              "extra_args": []},
    "dataset": {"path": DATASET, "type": "dataset",
                "name": "polyglot-bug-patterns", "extra_args": []},
}

# never upload these, whatever gitignore says
EXCLUDE = [
    "__pycache__/", "*.pyc", ".git/", ".venv/", "venv/", "artifacts/",
    "*.duckdb", "*.sqlite3", ".ipynb_checkpoints/", ".DS_Store",
    "node_modules/", "*.egg-info/", "demo-report.*", "pbhx-*.md",
]

# things people forget and then the Space breaks on a cold start
SPACE_MUST_HAVE = ["app.py", "README.md", "requirements.txt",
                   "packages.txt", "polyglot_bug_hunter/__init__.py"]
DATASET_MUST_HAVE = ["README.md", "data/payloads.jsonl", "data/findings.jsonl"]
MODEL_MUST_HAVE = ["README.md", "config.json", "payload_vocabulary.json"]


def check(kind: str) -> list[str]:
    """Cheap pre-flight so we find the missing file here, not in the browser."""
    spec = REPOS[kind]
    required = {"space": SPACE_MUST_HAVE, "dataset": DATASET_MUST_HAVE,
                "model": MODEL_MUST_HAVE,
                "static": ["index.html", "README.md", "assets/app.js",
                           "assets/scanner.js", "assets/i18n.js",
                           "assets/style.css", "package.json"]}[kind]
    problems = []
    for rel in required:
        if not (spec["path"] / rel).is_file():
            problems.append(f"missing {kind}/{rel}")
    if kind == "static":
        readme = spec["path"] / "README.md"
        if readme.is_file() and "sdk: static" not in readme.read_text(encoding="utf-8"):
            problems.append("static space README.md has no `sdk: static` frontmatter")
        if not (spec["path"] / "index.html").is_file():
            problems.append("static space has no index.html - it would serve a listing")
    if kind == "space":
        vendor = spec["path"] / "polyglot_bug_hunter"
        if not vendor.is_dir():
            problems.append("vendor copy missing - run: python tools/build_space.py")
        else:
            for locale_dir in ("locales",):
                if not (spec["path"] / locale_dir).is_dir():
                    problems.append(f"missing {locale_dir}/ in the space folder")
        readme = spec["path"] / "README.md"
        if readme.is_file() and "sdk: gradio" not in readme.read_text(encoding="utf-8"):
            problems.append("space README.md has no `sdk: gradio` frontmatter")
    if kind == "dataset":
        if not list((spec["path"] / "data").glob("*.parquet")):
            print("  note: no parquet found. `datasets.load_dataset` works with "
                  "JSONL, but parquet is faster:")
            print("        python tools/build_dataset.py   (needs duckdb)")
    if kind == "model":
        import json
        cfg = spec["path"] / "config.json"
        if cfg.is_file():
            try:
                json.loads(cfg.read_text(encoding="utf-8"))
            except Exception as exc:
                problems.append(f"config.json is not valid JSON: {exc}")
    return problems


def plan(kind: str, user: str, private: bool, dry: bool) -> int:
    spec = REPOS[kind]
    repo_id = f"{user}/{spec['name']}"
    rel = spec["path"].relative_to(ROOT)

    print(f"\n{'=' * 70}\n{kind.upper()}  ->  https://huggingface.co/{repo_id}\n{'=' * 70}")
    files = sorted(f for f in spec["path"].rglob("*")
                   if f.is_file() and "__pycache__" not in f.parts)
    print(f"  folder : {rel}")
    print(f"  files  : {len(files)}")
    print(f"  private: {private}")
    for f in files[:8]:
        print(f"           {f.relative_to(spec['path'])}")
    if len(files) > 8:
        print(f"           ... and {len(files) - 8} more")

    problems = check(kind)
    for p in problems:
        print(f"  !! {p}")
    if problems:
        print(f"  -> FIXED THIS FIRST, not uploading {kind}")
        return 1

    if dry:
        cmd = (f"huggingface-cli upload {repo_id} {rel} --repo-type {spec['type']} "
               + " ".join(spec["extra_args"]))
        if private:
            cmd += " --private"
        print(f"  DRY RUN. would run:\n    {cmd}")
        return 0

    from huggingface_hub import HfApi

    api = HfApi()
    # space_sdk belongs to create_repo, not upload_folder. Passing it to both
    # raised TypeError on upload_folder with huggingface_hub 1.33, which meant
    # every Space push failed after the repo was created - and the failure was
    # invisible because the "uploaded" line printed anyway from a different
    # code path. Verified against the installed signature at build time below.
    sdk = "gradio" if kind == "space" else "static"
    try:
        extra = {"space_sdk": sdk} if spec["type"] == "space" else {}
        api.create_repo(repo_id, repo_type=spec["type"], private=private,
                        exist_ok=True, **extra)
        print(f"  repo ensured: {repo_id}")
    except Exception as exc:
        print(f"  !! create_repo failed: {type(exc).__name__}: {exc}")
        return 1

    try:
        api.upload_folder(
            folder_path=str(spec["path"]),
            repo_id=repo_id,
            repo_type=spec["type"],
            ignore_patterns=EXCLUDE,
            commit_message=f"PolyglotBugHunter-X {_version()} release",
        )
    except Exception as exc:
        # Never print "uploaded" after a failed upload. That is how a broken
        # publish looked like a successful one.
        print(f"  !! upload failed: {type(exc).__name__}: {exc}")
        return 1
    print(f"  uploaded.  ->  https://huggingface.co/{repo_id}")
    if kind == "static":
        print("  a static space needs no build - it is live now. Pin it from the")
        print("  Space settings tab so it shows on your profile.")
    else:
        print("  watch the logs for the 'Running on local URL' line, then pin it.")
    return 0


def _version() -> str:
    """Read the version from pyproject without importing the package.

    publish.py runs before anything is installed, and importing the package to
    read its own version would make the tool depend on the thing it publishes.
    """
    txt = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    m = re.search(r'^version = "([^"]+)"', txt, re.M)
    return m.group(1) if m else "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--user", required=True, help="your HF username")
    ap.add_argument("--static", action="store_true",
                    help="the free static space (this is the live one)")
    ap.add_argument("--space", action="store_true",
                    help="the gradio space - REQUIRES an HF PRO subscription")
    ap.add_argument("--model", action="store_true")
    ap.add_argument("--dataset", action="store_true")
    ap.add_argument("--all", action="store_true",
                    help="model + dataset + static space (the gradio one needs PRO)")
    ap.add_argument("--private", action="store_true")
    ap.add_argument("--yes", action="store_true",
                    help="actually upload (default is a dry run)")
    args = ap.parse_args()

    if not any([args.static, args.space, args.model, args.dataset, args.all]):
        ap.error("pick at least one of --space --model --dataset --all")

    # static first: it is free, deployed, and the one people click
    kinds = (["model", "dataset", "static"] if args.all
             else [k for k in ("static", "space", "model", "dataset")
                   if getattr(args, k)])

    if not args.yes:
        print("DRY RUN - nothing will be uploaded. add --yes when you mean it.")

    rc = 0
    for kind in kinds:
        rc |= plan(kind, args.user, args.private, dry=not args.yes)

    print(f"\n{'=' * 70}")
    if not args.yes:
        print("Dry run complete. Review the plan, then re-run with --yes.")
    elif rc == 0:
        print("All done. Now:\n"
              "  1. open the static Space and click 🚀 Scan Example once\n"
              "  2. pin it on your profile\n"
              "  3. cross-link all three repos (README links are already in place,\n"
              "     just confirm the username is right)\n"
              "  4. read docs/GROWTH.md")
    return rc


if __name__ == "__main__":
    sys.exit(main())
