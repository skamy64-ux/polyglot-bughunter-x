#!/usr/bin/env python3
"""Assemble the uploadable HF Space folder.

The Space needs the library next to app.py, because a Space's install step is
just `pip install -r requirements.txt` - there is no `pip install -e .` and no
guarantee the parent repo exists. So we copy src/polyglot_bug_hunter and
locales/ into hf_space/ and give the whole thing a git-ignorable copy step.

Run:  python tools/build_space.py
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "polyglot_bug_hunter"
SPACE = ROOT / "hf_space"

COPY_PKG = [
    "__init__.py", "safety.py", "config.py", "models.py", "payloads.py",
    "i18n.py", "htmlx.py", "net.py", "hunter.py", "demo_target.py",
]
COPY_DIRS = ["scanner", "report", "storage", "vision", "speech", "agent"]
SKIP = {"__pycache__", ".pyc", ".mypy_cache", ".pytest_cache"}


def copy_tree(src: Path, dst: Path) -> int:
    dst.mkdir(parents=True, exist_ok=True)
    n = 0
    for item in src.iterdir():
        if item.name in SKIP:
            continue
        target = dst / item.name
        if item.is_dir():
            n += copy_tree(item, target)
        else:
            shutil.copy2(item, target)
            n += 1
    return n


def main() -> int:
    pkg_dst = SPACE / "polyglot_bug_hunter"
    if pkg_dst.exists():
        shutil.rmtree(pkg_dst)
    pkg_dst.mkdir(parents=True)

    total = 0
    for name in COPY_PKG:
        src = SRC / name
        if not src.exists():
            print(f"  ! missing {src}")
            continue
        shutil.copy2(src, pkg_dst / name)
        total += 1
    for d in COPY_DIRS:
        src = SRC / d
        if src.exists():
            total += copy_tree(src, pkg_dst / d)

    locale_dst = SPACE / "locales"
    if locale_dst.exists():
        shutil.rmtree(locale_dst)
    total += copy_tree(ROOT / "locales", locale_dst)

    print(f"space assembled: {total} files -> {SPACE}")
    print("  next: huggingface-cli upload <user>/polyglot-bughunter-x hf_space --repo-type space")
    return 0


if __name__ == "__main__":
    sys.exit(main())
