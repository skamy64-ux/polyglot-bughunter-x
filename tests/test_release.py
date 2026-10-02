"""Tests for tools/release.py.

The script's whole job is preventing a release that lands on four surfaces out
of five, so the drift detection is what matters here. Everything is tested
against real files rather than mocks: a drift check that only works on
fixtures is a drift check that breaks the first time it meets a real zip.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

spec = importlib.util.spec_from_file_location("release", TOOLS / "release.py")
rel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rel)


def test_every_destination_is_https():
    for name, url in rel.TARGETS.items():
        assert url.startswith("https://"), f"{name} is not https: {url}"


def test_targets_cover_all_five_surfaces():
    # a Space, a Model, a Dataset on HF; a Dataset and a Kernel on Kaggle
    assert {"space", "model", "hf-dataset", "kaggle-dataset", "kernel"} <= set(rel.TARGETS)
    # the CDN is checked too, because a Space can be 200 while serving nothing
    assert "space-cdn" in rel.TARGETS


def test_declared_version_matches_pyproject():
    assert rel.declared_version() == "1.0.0"


def test_drift_check_passes_on_a_freshly_built_tree():
    if not (ROOT / "kaggle_kernel" / "hf_demo.ipynb").is_file():
        pytest.skip("run: python tools/release.py --build")
    assert rel.check_drift() is True


def _fake_release_tree(tmp_path, pin: str):
    """Build the layout check_drift() actually reads.

    An earlier version of this test dumped everything in tmp_path root, so both
    branches were skipped and the check passed for the wrong reason - a green
    test that proved nothing. check_drift() looks under kaggle_dataset/ and
    kaggle_kernel/, so the fixture has to as well.
    """
    import base64
    import shutil

    whls = sorted((ROOT / "kaggle_dataset").glob("*.whl"))
    if not whls:
        pytest.skip("run: python tools/build_kaggle.py")

    (tmp_path / "pyproject.toml").write_text('version = "1.0.0"\n')
    raw = base64.b64encode(whls[0].read_bytes()).decode()

    (tmp_path / "kaggle_dataset").mkdir()
    shutil.copy2(whls[0], tmp_path / "kaggle_dataset" / whls[0].name)
    (tmp_path / "kaggle_dataset" / "hf_demo.ipynb").write_text(json.dumps({"cells": [
        {"cell_type": "code", "source": ['glob.glob("/kaggle/input/*/*.whl")\n']}]}))

    (tmp_path / "kaggle_kernel").mkdir()
    (tmp_path / "kaggle_kernel" / "hf_demo.ipynb").write_text(json.dumps({"cells": [
        {"cell_type": "code", "source": [
            f'_whl = "polyglot_bug_hunter_x-{pin}-py3-none-any.whl"\n',
            f'_WHEEL_B64 = """\n{raw}\n"""\n']},
    ]}))
    return whls[0]


def test_drift_check_notices_a_version_mismatch(tmp_path, monkeypatch):
    """The pin baked into the kernel must follow pyproject.

    A version bump that does not rebuild the kernel leaves it running the old
    code, silently, and that is the exact failure this script exists to stop.
    """
    _fake_release_tree(tmp_path, pin="0.9.0")
    monkeypatch.setattr(rel, "ROOT", tmp_path)
    assert rel.check_drift() is False, "a stale pin must fail the drift check"


def test_drift_check_passes_when_the_pin_matches(tmp_path, monkeypatch):
    _fake_release_tree(tmp_path, pin="1.0.0")
    monkeypatch.setattr(rel, "ROOT", tmp_path)
    assert rel.check_drift() is True


def test_drift_check_notices_different_code(tmp_path, monkeypatch):
    """Two wheels that build the same version but different code still drift."""
    import base64
    import io
    import zipfile

    whl = _fake_release_tree(tmp_path, pin="1.0.0")

    # forge a wheel with the same version but a different file inside
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        with zipfile.ZipFile(whl) as src:
            for n in src.namelist():
                data = src.read(n)
                if n.endswith("__init__.py"):
                    data = data + b"\n# tampered\n"
                out.writestr(n, data)
    forged = base64.b64encode(buf.getvalue()).decode()

    (tmp_path / "kaggle_kernel" / "hf_demo.ipynb").write_text(json.dumps({"cells": [
        {"cell_type": "code", "source": [
            '_whl = "polyglot_bug_hunter_x-1.0.0-py3-none-any.whl"\n',
            f'_WHEEL_B64 = """\n{forged}\n"""\n']},
    ]}))
    monkeypatch.setattr(rel, "ROOT", tmp_path)
    assert rel.check_drift() is False, "differing code must fail even at one version"


def test_wheel_extraction_rejects_a_notebook_carrying_nothing(tmp_path):
    nb = tmp_path / "x.ipynb"
    nb.write_text(json.dumps({"cells": [
        {"cell_type": "code", "source": ["print(1)\n"]}]}))
    with pytest.raises(SystemExit):
        rel.wheel_from_notebook(nb)


def test_wheel_extraction_handles_both_shapes(tmp_path):
    import base64
    import zipfile

    whls = sorted((ROOT / "kaggle_dataset").glob("*.whl"))
    if not whls:
        pytest.skip("run: python tools/build_kaggle.py")

    # file-shaped
    file_nb = tmp_path / "file.ipynb"
    file_nb.write_text(json.dumps({"cells": [
        {"cell_type": "code", "source": ['glob.glob("/kaggle/input/*/*.whl")\n']}]}))
    assert rel.wheel_from_notebook(file_nb) is None

    # inline-shaped
    raw = base64.b64encode(whls[0].read_bytes()).decode()
    inline_nb = tmp_path / "inline.ipynb"
    inline_nb.write_text(json.dumps({"cells": [
        {"cell_type": "code",
         "source": [f'_WHEEL_B64 = """\n{raw}\n"""\n']}]}))
    got = rel.wheel_from_notebook(inline_nb)
    assert isinstance(got, dict) and "polyglot_bug_hunter/__init__.py" in got
    assert zipfile.is_zipfile(whls[0])


def test_verify_uses_no_credentials(monkeypatch):
    """An authenticated 200 proves nothing about a public release.

    With a token loaded, both hosts answer 200 for private repos, so a broken
    publish would read as a success. The verifier must stay anonymous.
    """
    import inspect

    src = inspect.getsource(rel.do_verify)
    for forbidden in ("KAGGLE_API_TOKEN", "HF_TOKEN", "kaggle.json", "login"):
        assert forbidden not in src, f"do_verify touches {forbidden}"


def test_verify_targets_are_reachable():
    bad = []
    for name, url in rel.TARGETS.items():
        code = rel._probe(url)
        if code != 200:
            bad.append(f"{name} -> {code}")
    assert not bad, f"not live: {bad}"


def test_probe_uses_get_not_head():
    """Kaggle answers 404 to every HEAD request, repo or not.

    It does not implement the method, so a HEAD-based verifier reports a
    perfectly healthy dataset as deleted. Found because curl -X HEAD returned
    404 on a dataset that GET returned 200 for.
    """
    import inspect

    src = inspect.getsource(rel._probe)
    assert 'method="HEAD"' not in src
    assert 'method=\"HEAD\"' not in src


def test_probe_sends_a_browser_user_agent():
    """A bot agent gets 404 from Kaggle, same as a missing repo."""
    import inspect

    src = inspect.getsource(rel._probe)
    assert "Chrome/" in src, "Kaggle 404s a non-browser User-Agent"
    assert "compatible;" not in src, "a bot agent looks like a deleted repo"


def test_dry_run_uploads_nothing(tmp_path):
    p = subprocess.run(
        [sys.executable, str(TOOLS / "release.py"), "--all", "--dry-run"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0
    assert "nothing will be uploaded" in p.stdout
    # it must not have built anything
    assert not (ROOT / "kaggle_kernel" / ".uploaded").exists()


def test_unknown_target_is_rejected():
    p = subprocess.run(
        [sys.executable, str(TOOLS / "release.py"), "--publish", "--only", "nope"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 2
    assert "unknown target" in p.stderr


def test_help_lists_every_target():
    p = subprocess.run(
        [sys.executable, str(TOOLS / "release.py"), "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0
    for name in rel.TARGETS:
        assert name in p.stdout, f"{name} is not offered on the command line"
