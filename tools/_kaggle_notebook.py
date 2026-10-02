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

import base64
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


def install_cell(wheel: Path) -> list[str]:
    """The install cell, with the wheel inlined as base64.

    Four ways this was tried before it worked, all of which looked fine locally
    and failed in the kernel log:

    - install by PyPI name -> the project is not published there
    - `pip install ./package` -> Kaggle does not upload the folder
    - a source tree beside the notebook -> same reason
    - a plain `.whl` beside the notebook -> `glob` came back empty

    Kaggle uploads the notebook itself, so the artifact has to be a cell. The
    `is_zipfile` assertion means a truncated paste shows up as one clear line
    instead of a confusing pip error.
    """
    blob = base64.b64encode(wheel.read_bytes()).decode("ascii")
    chunks = [blob[i:i + 76] for i in range(0, len(blob), 76)]

    lines = [
        "import base64, subprocess, sys, zipfile\n",
        "from pathlib import Path\n",
        "\n",
        "# The package is not on PyPI and the GitHub repo may not exist yet, so\n",
        "# the wheel is inlined. Kaggle uploads the notebook and nothing else, so\n",
        "# this is the one place the artifact cannot be lost on the way in.\n",
        "# Regenerate with: python tools/build_kaggle.py\n",
        "_WHEEL_B64 = \"\"\"\n",
    ]
    lines += [f"{c}\n" for c in chunks]
    lines += [
        "\"\"\"\n",
        "\n",
        f"_whl = {WHEEL_NAME!r}\n",
        "with open(_whl, \"wb\") as _fh:\n",
        "    _fh.write(base64.b64decode(_WHEEL_B64))\n",
        "\n",
        "assert zipfile.is_zipfile(_whl), \"inlined wheel is not a valid zip\"\n",
        "print(f\"installed from inlined wheel ({Path(_whl).stat().st_size} bytes)\")\n",
        "subprocess.run([sys.executable, \"-m\", \"pip\", \"install\", \"-q\", _whl],\n",
        "               check=True)\n",
        "# Optional, all degrade gracefully:\n",
        "#   duckdb  pillow  faster-whisper  playwright\n",
    ]
    return lines


#: Matches the install cell in any notebook, whoever wrote it.
INSTALL_RE = re.compile(r'^\s*(!pip install|%pip install|.*_WHEEL_B64)')


def has_install_cell(nb: dict) -> bool:
    return any(
        c.get("cell_type") == "code" and INSTALL_RE.match("".join(c.get("source", [])))
        for c in nb.get("cells", [])
    )


def rewrite_install(nb: dict, wheel: Path) -> dict:
    """Swap whatever install cell exists for the inlined-wheel one.

    The original is a shell escape (`!pip install`), so a filter looking for
    the magic form `%pip install` does not see it. Matching both, plus
    "already ours", is what stops a stale PyPI install surviving into a
    published notebook.
    """
    cells = []
    replaced = False
    for cell in nb.get("cells", []):
        if cell.get("cell_type") != "code":
            cells.append(cell)
            continue
        src = "".join(cell.get("source", []))
        if INSTALL_RE.match(src):
            cell = dict(cell)
            cell["source"] = install_cell(wheel)
            cell["execution_count"] = None
            cell["outputs"] = []
            replaced = True
        cells.append(cell)

    if not replaced:
        raise SystemExit(
            "the notebook has no install cell to rewrite. That means the package "
            "will not be importable. Fix tools/build_notebook.py."
        )

    for cell in cells:
        if cell.get("cell_type") == "code":
            cell["execution_count"] = None
            cell["outputs"] = []
    nb["cells"] = cells
    return nb
