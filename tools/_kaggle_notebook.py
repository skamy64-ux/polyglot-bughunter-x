#!/usr/bin/env python3
"""Shared helpers for the two Kaggle builders.

Both the dataset and the kernel ship the same notebook, and both hit the same
constraint: Kaggle uploads the notebook and its metadata and nothing else, and
the package is not on PyPI. So the wheel has to travel inside the notebook.

Keeping this in one place stops the two builders from drifting, which is
exactly how `enable_free_internet` vs `enable_internet` and `public` vs
`is_private` slipped through.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = "polyglot_bug_hunter"

#: Everything in the notebook's install cell is derived from this, so a version
#: bump can never leave a stale wheel name baked into a string.
VERSION = "1.0.0"
WHEEL_NAME = f"{PKG}_x-{VERSION}-py3-none-any.whl"


def build_wheel(dest_dir: Path) -> Path:
    """Build the package wheel into `dest_dir` and return its path."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", tmp, str(ROOT)]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=900)
        except subprocess.CalledProcessError as exc:
            print("error: pip wheel failed\n", file=sys.stderr)
            print((exc.stderr or exc.stdout or "")[-2000:], file=sys.stderr)
            raise
        wheels = sorted(Path(tmp).glob("*.whl"))
        if not wheels:
            print("error: pip wheel produced no .whl", file=sys.stderr)
            raise SystemExit(2)
        out = dest_dir / wheels[0].name
        shutil.copy2(wheels[0], out)
        return out


def install_cell() -> list[str]:
    """The install cell: find the wheel, install it, say clearly if it is gone.

    This used to inline the wheel as base64, which worked but was the worst
    thing in the repository: a 180 KB notebook of unreadable base64, rebuilds
    that never converge byte-for-byte because a zip embeds a timestamp, and a
    truncated paste that surfaces as a confusing pip error.

    The wheel ships as an ordinary file in the Kaggle dataset instead, which is
    what Kaggle's own "Add notebook -> attach dataset" flow is for. The notebook
    drops back to 17 KB and reads like a notebook again.

    Sources are tried in order of how likely they are to work on Kaggle:
      1. the attached dataset, which is how the notebook is meant to be run
      2. a wheel built next to the notebook, for a local or CI run
      3. nothing - and then say exactly what to do about it
    """
    return [
        "import glob, os, subprocess, sys\n",
        "\n",
        "# The package is not on PyPI, so it cannot be pip installed by name.\n",
        "# It ships as a file in this dataset instead: on Kaggle it arrives via\n",
        "# \"Add notebook -> Input -> polyglot-bug-patterns\". Locally it is built\n",
        "# by:  python tools/build_kaggle.py\n",
        "_candidates = (\n",
        "    glob.glob(\"/kaggle/input/polyglot-bug-patterns/*.whl\"),   # attached dataset\n",
        "    glob.glob(\"/kaggle/input/*/*.whl\"),                       # any attached dataset\n",
        "    glob.glob(\"*.whl\"),                                       # built alongside\n",
        "    glob.glob(\"../*.whl\"),\n",
        ")\n",
        "_wheel = next((w for group in _candidates for w in group), None)\n",
        "\n",
        "if _wheel is None:\n",
        "    raise SystemExit(\n",
        "        \"Could not find polyglot_bug_hunter*.whl.\\n\\n\"\n",
        "        \"  On Kaggle: add this dataset as notebook input.\\n\"\n",
        "        \"  Locally:   python tools/build_kaggle.py\\n\\n\"\n",
        "        \"  Or install the source directly: pip install -e .\"\n",
        "    )\n",
        "\n",
        "print(f\"installing {_wheel} ({os.path.getsize(_wheel)} bytes)\")\n",
        "subprocess.run([sys.executable, \"-m\", \"pip\", \"install\", \"-q\", _wheel],\n",
        "               check=True)\n",
        "# Optional, all degrade gracefully:\n",
        "#   duckdb  pillow  faster-whisper  playwright\n",
    ]


#: Matches the install cell in any notebook, whoever wrote it.
INSTALL_RE = re.compile(
    r"^\s*(!pip install|%pip install|.*_wheel = next\(|.*_WHEEL_B64)")


def has_install_cell(nb: dict) -> bool:
    return any(
        c.get("cell_type") == "code" and INSTALL_RE.match("".join(c.get("source", [])))
        for c in nb.get("cells", [])
    )


def rewrite_install(nb: dict, cell_body: list[str] | None = None) -> dict:
    """Swap whatever install cell exists for a working one.

    The original is a shell escape (`!pip install`), so a filter looking for
    the magic form `%pip install` does not see it. Matching both, plus
    "already ours", is what stops a stale PyPI install surviving into a
    published notebook.

    `cell_body` overrides the replacement. The dataset notebook installs from a
    dataset file; the kernel inlines a wheel instead, so it is not a consumer
    of any attached input.
    """
    cells = []
    replaced = False
    for existing in nb.get("cells", []):
        if existing.get("cell_type") != "code":
            cells.append(existing)
            continue
        if INSTALL_RE.match("".join(existing.get("source", []))):
            new = dict(existing)
            new["source"] = cell_body or install_cell()
            new["execution_count"] = None
            new["outputs"] = []
            cells.append(new)
            replaced = True
        else:
            cells.append(existing)

    if not replaced:
        raise SystemExit(
            "the notebook has no install cell to rewrite. That means the package "
            "will not be importable. Fix tools/build_notebook.py."
        )

    for existing in cells:
        if existing.get("cell_type") == "code":
            existing["execution_count"] = None
            existing["outputs"] = []
    nb["cells"] = cells
    return nb
