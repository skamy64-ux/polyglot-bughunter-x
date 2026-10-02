#!/usr/bin/env python3
"""Assemble a Kaggle-ready notebook (Kernel) folder.

The dataset is on Kaggle but the notebook is not, which is backwards: a dataset
of attack payloads with nothing to run them in is a table, not a demo. Kaggle
Kernels are the natural home - free CPU, 30 GPU-hours a week, and anyone can
"Copy & Edit" it.

Kernels want `kernel-metadata.json`, not `dataset-metadata.json`, and the field
names overlap only partially. This builds `kaggle_kernel/` from the same notebook
that ships to Hugging Face.

```bash
python tools/build_kaggle_kernel.py
kaggle kernels push -p kaggle_kernel
```

The notebook runs entirely offline: it boots the bundled vulnerable target on
localhost and scans it. No credentials, no external host, no GPU.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _kaggle_notebook import REPO_TAG, VCS_URL, rewrite_install

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = ROOT / "notebooks" / "hf_demo.ipynb"
OUT = ROOT / "kaggle_kernel"

# Kaggle's accelerator enum. "none" is the safe default: the demo needs no GPU
# and asking for one wastes quota.
ACCELERATOR = "none"

#: Kaggle slugifies the title to build the URL, and warns when the result does
#: not match the id you asked for. Keeping them in sync means the URL is
#: predictable and the push is not a warning about a redirect.
TITLE = "polyglot-bug-patterns-demo"
SUBTITLE = "Run the detector offline, then load the payload tables as Parquet."


def kernel_install_cell() -> list[str]:
    """The kernel's install cell.

    Three attempts got here, and why the third one works is worth recording:

    - 110 KB of base64 inlined in the notebook: it works, and it is unreadable.
      A build artifact nobody can review or diff, and a truncated paste
      surfaces as a pip error with no context.
    - pip install from the Git tag: a 17 KB notebook, right up until the kernel
      ran with enable_internet off and `git clone` exited 128. The tag is right
      for a reader with a network and useless inside a kernel that has none.
    - the wheel attached as a dataset: Kaggle mounts an attached dataset without
      needing a network, which is precisely the situation this kernel is in.

    So the dataset comes first and the ref is the fallback, which means the
    kernel needs no internet, and so does anyone who copies the cell elsewhere.
    """

    return [
        "import glob, subprocess, sys\n",
        "\n",
        "# The kernel runs with enable_internet off, so the package arrives as a\n",
        "# file attached from the companion dataset. The Git tag is the fallback\n",
        "# for anyone running this cell outside Kaggle, where there is a network.\n",
        "_wheel = None\n",
        "for _pattern in (\"/kaggle/input/polyglot-bug-patterns/*.whl\",\n",
        "                 \"/kaggle/input/*/*.whl\",\n",
        "                 \"*.whl\", \"../*.whl\"):\n",
        "    _hits = glob.glob(_pattern)\n",
        "    if _hits:\n",
        "        _wheel = _hits[0]\n",
        "        break\n",
        "\n",
        "if _wheel is None:\n",
        f"    _wheel = {VCS_URL!r}\n",
        "\n",
        "print(f\"installing {_wheel}\")\n",
        "subprocess.run([sys.executable, \"-m\", \"pip\", \"install\", \"-q\", _wheel],\n",
        "               check=True)\n",
        "# Optional, all degrade gracefully:\n",
        "#   duckdb  pillow  faster-whisper  playwright\n",
    ]


def kernel_metadata(owner: str) -> dict:
    return {
        "id": f"{owner}/polyglot-bug-patterns-demo",
        "title": TITLE,
        "code_file": "hf_demo.ipynb",
        "language": "python",
        # Kaggle rejects the push outright without this; it is not optional and
        # not inferable from the file extension.
        "kernel_type": "notebook",
        # Kaggle validates this too; keep it inside the range or the push is
        # rejected before the notebook is even parsed
        "subtitle": SUBTITLE,
        "description": (
            "Companion notebook for the **Polyglot Bug Patterns** dataset.\n\n"
            "Runs the detector against a deliberately vulnerable app on "
            "localhost - no external traffic, no credentials - then loads the "
            "shipped Parquet tables so you can slice them: 43 payloads across "
            "8 bug classes (24 polyglot), CVSS v3.1 scored, mapped to CWE and "
            "OWASP, with a companion findings table showing which evidence "
            "proves each bug.\n\n"
            "Every payload passes the same non-destructive gate the scanner "
            "applies at runtime. Use them only against systems you own or have "
            "written permission to test.\n\n"
            "**Dataset:** https://www.kaggle.com/datasets/simonmarc/polyglot-bug-patterns\n"
            "**Live demo:** https://huggingface.co/spaces/Kicaulah/polyglot-bughunter-x-static"
        ),
        # Deliberately empty. Kernels and datasets do NOT share a tag
        # vocabulary: "cyber security" is accepted by `datasets create` and
        # rejected here with "not valid tags". An empty list is a clean push;
        # a rejected tag is a warning on every version.
        "keywords": [],
        "cpu_count": 2,
        "memory": {"total": 4, "disk": 1, "kernel_cpu": 2, "kernel_gpu": 0,
                   "kernel_memory": 2048},
        "enable_gpu": ACCELERATOR == "gpu",
        "enable_tpu": ACCELERATOR == "tpu",
        # Kernels are private by default and the CLI has no visibility flag, so
        # this key is the only way to publish one. Without it the page 404s for
        # everyone but the owner even though the run is COMPLETE.
        #
        # The key is is_private, not "public": writing "public": "true" is
        # silently ignored, which is what a `kaggle kernels pull` reveals. The
        # round-tripped metadata does not even contain a "public" key.
        "is_private": False,
        # The key is enable_internet, NOT enable_free_internet. We sent the
        # latter for several versions and the kernel ran with internet on the
        # whole time - the same silently-ignored-key bug as "public" above.
        # A `kaggle kernels pull -m` is the only way to see this: the stored
        # document has enable_internet and no enable_free_internet at all.
        #
        # It stays off. The demo is a local loopback scan and needs no network
        # at runtime, so there is no reason to hand the kernel one. The cost is
        # that pip cannot reach a URL here - which is why the wheel is attached
        # below rather than fetched.
        "enable_internet": False,
        # Attach our own dataset, so the wheel arrives as a file and the
        # notebook installs offline.
        #
        # This is the mechanism that makes a 17 KB notebook possible. Both
        # alternatives failed in practice: inlining 110 KB of base64 produced a
        # notebook nobody could read or diff, and switching the kernel to a git
        # ref made `git clone` exit 128 under a kernel that deliberately has no
        # internet. Kaggle mounts an attached dataset for free and needs no
        # network to do it, so that is what this uses.
        "dataset_sources": [f"{owner}/polyglot-bug-patterns"],
        "competition_data": [],
    }


def build_wheel() -> Path:
    """Build a wheel of the package and return its path.

    Uses the `build` module if it is available and falls back to
    `setup.py`-free `pip wheel`, which still works with only pip installed.
    """
    import subprocess
    import sys
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        cmd = [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", tmp,
               str(ROOT)]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=900)
        except FileNotFoundError as exc:  # pragma: no cover
            print(f"error: cannot run pip: {exc}", file=sys.stderr)
            raise
        except subprocess.CalledProcessError as exc:
            print("error: pip wheel failed\n", file=sys.stderr)
            print((exc.stderr or exc.stdout or "")[-2000:], file=sys.stderr)
            raise

        wheels = sorted(Path(tmp).glob("*.whl"))
        if not wheels:
            print("error: pip wheel produced no .whl", file=sys.stderr)
            raise SystemExit(2)
        # exactly one wheel, named polyglot_bug_hunter-1.0.0-py3-none-any.whl
        dest = OUT / wheels[0].name
        shutil.copy2(wheels[0], dest)
        return dest


def main() -> int:
    if not NOTEBOOK.is_file():
        print(f"error: {NOTEBOOK} is missing. run: python tools/build_notebook.py",
              file=sys.stderr)
        return 2

    if OUT.exists():
        shutil.rmtree(OUT)
    # The notebook writes reports and a canary into the working directory, so
    # they end up inside the kernel folder after any local run. Push the folder
    # without wiping it and Kaggle uploads the debris too.
    OUT.mkdir(parents=True)

    # The wheel is built first: the install cell inlines it, so the notebook
    # cannot be written until the artifact exists.
    #
    # The kernel keeps the inlined copy even though the dataset now ships a
    # wheel file. A kernel can attach datasets too, but only via the web UI or
    # the `dataset_sources` metadata field, and a notebook that fails when
    # nobody remembered to click "Add input" is a worse default than a large
    # one. The dataset notebook uses the file; the kernel is self-contained.
    wheel = build_wheel()
    doc = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    doc = rewrite_install(doc, cell_body=kernel_install_cell())
    (OUT / "hf_demo.ipynb").write_text(
        json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    metadata = kernel_metadata(_owner())
    (OUT / "kernel-metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    code_cells = sum(1 for c in doc["cells"] if c["cell_type"] == "code")
    installs = [c for c in doc["cells"] if c["cell_type"] == "code"
                and "pip" in "".join(c["source"])]
    assert installs, ("the notebook must keep an install cell: Kaggle's image "
                      "does not carry the package")
    assert wheel.is_file() and wheel.stat().st_size > 10_000, \
        f"the wheel looks wrong: {wheel} ({wheel.stat().st_size if wheel.is_file() else 0} bytes)"
    # the name is not on PyPI; installing it by name silently fails
    assert not any("pip install -q polyglot-bug-hunter-x" in "".join(c["source"])
                   for c in installs), \
        "do not install by PyPI name, the project is not published there"
    # The ref must be a tag, not a branch: a published kernel that tracks a
    # moving branch starts running different code on the next re-run.
    _cell = "".join(installs[0]["source"])
    assert REPO_TAG in _cell, "the kernel must install from the pinned tag"
    assert "@main" not in _cell and "@master" not in _cell, \
        "installing from a branch means the published notebook can change underneath you"
    assert 20 <= len(metadata["subtitle"]) <= 80, \
        f"kaggle wants a 20-80 char subtitle, got {len(metadata['subtitle'])}"
    assert 5 <= len(metadata["title"]) <= 100, \
        f"kaggle wants a 5-100 char title, got {len(metadata['title'])}"
    assert (OUT / metadata["code_file"]).is_file(), "code_file is missing"

    print(f"kernel    : {metadata['id']}")
    print(f"subtitle  : {len(metadata['subtitle'])} chars (kaggle wants 20-80)")
    print(f"assembled : {code_cells} code cells, offline install from the attached dataset")
    print(f"           -> {OUT}")
    print()
    print("  push with:")
    print("    kaggle kernels push -p kaggle_kernel")
    print()
    print("  the notebook pip-installs the wheel from the attached dataset (no")
    print("  network needed) and falls back to the Git tag elsewhere. then it")
    print("  boots its own vulnerable target on localhost.")
    return 0


def _owner() -> str:
    """Reuse the dataset builder's owner resolution so the two cannot drift."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from build_kaggle import kaggle_username

    return kaggle_username()


if __name__ == "__main__":
    sys.exit(main())
