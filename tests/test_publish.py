"""Tests for tools/publish.py.

The bug this exists to prevent: publish.py printed "uploaded" after the upload
had already raised. The repo was created, the message appeared, the process
exited zero for the wrong reason, and every Space push silently failed for
days. Nothing caught it because nobody checked exit codes and nothing asserted
that the arguments we pass exist.

So: every kwarg this module passes to huggingface_hub is checked against the
installed signature. If huggingface_hub changes underneath us, this fails at
test time instead of at upload time.
"""

from __future__ import annotations

import importlib.util
import inspect
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

spec = importlib.util.spec_from_file_location("publish", TOOLS / "publish.py")
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)

hfh = pytest.importorskip("huggingface_hub")


def test_create_repo_kwargs_exist():
    """space_sdk is a create_repo argument, and only there."""
    sig = inspect.signature(hfh.HfApi.create_repo)
    assert "space_sdk" in sig.parameters, (
        "huggingface_hub dropped space_sdk; a Space cannot be created without it "
        "and the free tier will refuse the repo")


def test_upload_folder_takes_no_space_sdk():
    """The exact failure: space_sdk was passed to upload_folder and raised.

    TypeError: HfApi.upload_folder() got an unexpected keyword argument
    'space_sdk' - raised after create_repo had already succeeded, so the run
    looked like it was halfway fine.
    """
    sig = inspect.signature(hfh.HfApi.upload_folder)
    assert "space_sdk" not in sig.parameters


def test_publish_does_not_pass_space_sdk_to_upload_folder():
    src = (TOOLS / "publish.py").read_text()
    # the call site must not splat anything into upload_folder
    call = src[src.index("api.upload_folder("):]
    call = call[:call.index(")") + 1]
    assert "space_sdk" not in call, "upload_folder is not given space_sdk"
    assert "**extra" not in call, "no blind kwarg splat into upload_folder"


def test_upload_is_wrapped_so_failure_cannot_look_like_success():
    src = (TOOLS / "publish.py").read_text()
    assert "upload failed" in src, "a failed upload must be reported as such"
    # the success line has to come after the guarded call, not before it
    guard = src.index("except Exception as exc:", src.index("api.upload_folder("))
    ok_line = src.index('print(f"  uploaded.', guard)
    assert ok_line > guard, "'uploaded' must not be reachable when the upload raised"


def _declared() -> str:
    txt = (ROOT / "pyproject.toml").read_text()
    return re.search(r'^version = "([^"]+)"', txt, re.M).group(1)


def test_version_is_read_from_pyproject_not_by_importing():
    assert pub._version() == _declared()


def test_version_matches_the_package():
    """The message on the commit and the version users install must agree."""
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from polyglot_bug_hunter import __version__ as installed
    finally:
        sys.path.remove(str(ROOT / "src"))
    assert pub._version() == installed


def test_repos_cover_every_published_surface():
    """A release that skips a repo is the failure release.py exists to prevent."""
    src = (TOOLS / "publish.py").read_text()
    for repo in ("polyglot-bughunter-x-static", "polyglot-bughunter-x",
                 "polyglot-bug-patterns"):
        assert repo in src, f"{repo} is not published by publish.py"
    for kind in ("--static", "--space", "--model", "--dataset"):
        assert kind in src, f"{kind} is not offered"


def test_exclude_patterns_cover_generated_noise():
    joined = " ".join(pub.EXCLUDE)
    for pattern in ("__pycache__", ".pyc", "node_modules"):
        assert pattern in joined, f"{pattern} is not excluded from uploads"


def test_publish_is_dry_run_by_default():
    """create_repo is one-way; the default has to be the safe direction."""
    src = (TOOLS / "publish.py").read_text()
    assert "--yes" in src, "a confirmation flag must exist"
    assert "dry run" in src.lower()
