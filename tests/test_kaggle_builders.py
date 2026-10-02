"""Tests for tools/build_kaggle.py and tools/build_kaggle_kernel.py.

The Kaggle builders are pure string/metadata work, but the failures they exist
to prevent are expensive: a bad subtitle or a missing `kernel_type` is a
rejected push, and a dropped artifact is a red kernel. Both were real bugs
during development, so both are asserted here rather than left to a live push.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import re
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))


def _notebook_source(path: Path) -> str:
    doc = json.loads(path.read_text())
    return "\n".join("".join(c.get("source", [])) for c in doc["cells"])


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ds = load("build_kaggle")
kn = load("build_kaggle_kernel")


# --- dataset metadata ------------------------------------------------------


def test_dataset_notebook_can_actually_install():
    """The notebook shipped in the dataset must run for whoever downloads it.

    It used to carry `!pip install -q polyglot-bug-hunter-x`, and the project
    is not on PyPI, so that cell failed outright. That made the dataset a table
    of strings rather than a runnable demo.

    It now globs for the wheel that ships as a dataset file, which is Kaggle's
    own "Add notebook -> Input" flow, rather than carrying 180 KB of base64.
    """
    nb_path = ROOT / "kaggle_dataset" / "hf_demo.ipynb"
    if not nb_path.is_file():
        pytest.skip("run: python tools/build_kaggle.py")
    src = _notebook_source(nb_path)
    assert "pip install -q polyglot-bug-hunter-x" not in src, \
        "installs by PyPI name, which does not exist"
    assert "_WHEEL_B64" not in src, \
        "the dataset notebook should not inline the wheel; it ships as a file"
    assert "/kaggle/input" in src, "must look for the attached dataset"
    assert "*.whl" in src


def test_dataset_ships_a_valid_wheel_file():
    """The notebook globs for a .whl, so a .whl has to actually be in the dataset."""
    whls = sorted((ROOT / "kaggle_dataset").glob("*.whl"))
    if not whls:
        pytest.skip("run: python tools/build_kaggle.py")
    assert len(whls) == 1, f"expected one wheel, found {len(whls)}"
    with zipfile.ZipFile(whls[0]) as z:
        names = z.namelist()
    assert "polyglot_bug_hunter/__init__.py" in names
    assert "polyglot_bug_hunter/cli.py" in names


def test_dataset_metadata_documents_the_wheel():
    meta_path = ROOT / "kaggle_dataset" / "dataset-metadata.json"
    if not meta_path.is_file():
        pytest.skip("run: python tools/build_kaggle.py")
    meta = json.loads(meta_path.read_text())
    listed = {r["path"] for r in meta["resources"]}
    whls = list((ROOT / "kaggle_dataset").glob("*.whl"))
    if whls:
        assert whls[0].name in listed, \
            "the wheel ships but is not listed as a Kaggle resource"


def test_dataset_notebook_error_message_is_actionable():
    """A missing wheel must say what to do, not raise a raw pip error."""
    nb_path = ROOT / "kaggle_dataset" / "hf_demo.ipynb"
    if not nb_path.is_file():
        pytest.skip("run: python tools/build_kaggle.py")
    src = _notebook_source(nb_path)
    assert "Could not find" in src
    assert "Add notebook" in src or "add this dataset" in src.lower()
    assert "tools/build_kaggle.py" in src


def test_both_notebooks_ship_the_same_code():
    """Drift between the two builders is how enable_free_internet happened.

    The shapes differ on purpose - the kernel inlines the wheel because a
    kernel must work on the first click, the dataset notebook globs for a file -
    but the code inside them must be identical.

    Comparison is over extracted contents, not file bytes: a wheel is a zip, a
    zip embeds a build timestamp, and two builds of identical source differ in
    6 of 32 entries' date_time while every extracted file is byte-identical. A
    whole-file hash would fail on every rebuild and teach people to ignore it.
    """
    ds_nb = ROOT / "kaggle_dataset" / "hf_demo.ipynb"
    k_nb = ROOT / "kaggle_kernel" / "hf_demo.ipynb"
    whls = sorted((ROOT / "kaggle_dataset").glob("*.whl"))
    if not (ds_nb.is_file() and k_nb.is_file() and whls):
        pytest.skip("run both builders")

    def hashes(z):
        return {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()}

    with zipfile.ZipFile(whls[0]) as z:
        a = hashes(z)

    k_src = _notebook_source(k_nb)
    m = re.search(r'_WHEEL_B64 = """\n(.*?)"""', k_src, re.S)
    assert m, "the kernel must inline its wheel"
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(m.group(1)))) as z:
        b = hashes(z)

    assert set(a) == set(b), "the two wheels hold different files"
    differing = {n for n in a if a[n] != b[n]}
    assert not differing, f"dataset and kernel ship different code: {sorted(differing)}"


def test_kernel_still_inlines_its_wheel():
    """Deliberate asymmetry: a kernel cannot rely on attached input.

    The dataset notebook was switched to a wheel file, and it would have been
    easy to switch the kernel too. It must not: the kernel is what someone
    lands on from the dataset page, and it has to work on the first click with
    nobody having pressed "Add input".
    """
    k_nb = ROOT / "kaggle_kernel" / "hf_demo.ipynb"
    if not k_nb.is_file():
        pytest.skip("run: python tools/build_kaggle_kernel.py")
    src = _notebook_source(k_nb)
    assert "_WHEEL_B64" in src
    assert "/kaggle/input" not in src, \
        "the kernel must not depend on an attached dataset"


def test_shared_helper_version_matches_pyproject():
    """A version bump must not leave a stale wheel name in a string literal."""
    import _kaggle_notebook as kn

    declared = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(),
                         re.M).group(1)
    assert declared == kn.VERSION, \
        f"_kaggle_notebook.VERSION is {kn.VERSION}, pyproject says {declared}"
    assert kn.WHEEL_NAME.endswith(f"-{declared}-py3-none-any.whl")


def test_rewrite_install_refuses_a_notebook_with_no_install_cell():
    import _kaggle_notebook as kn

    nb = {"cells": [{"cell_type": "code", "source": ["print(1)\n"],
                     "execution_count": 1, "outputs": [{"x": 1}]}]}
    with pytest.raises(SystemExit):
        kn.rewrite_install(nb, ROOT / "pyproject.toml")


def test_rewrite_install_clears_stale_outputs():
    import _kaggle_notebook as kn

    nb = {"cells": [{"cell_type": "code", "source": ["!pip install foo\n"],
                     "execution_count": 7, "outputs": [{"output_type": "stream"}]}]}
    out = kn.rewrite_install(nb)
    cell = out["cells"][0]
    assert cell["outputs"] == []
    assert cell["execution_count"] is None
    assert "/kaggle/input" in "".join(cell["source"])


def test_rewrite_install_accepts_a_cell_override():
    """The kernel supplies its own inline cell; the shared rewriter must honour it."""
    import _kaggle_notebook as kn

    nb = {"cells": [{"cell_type": "code", "source": ["!pip install foo\n"],
                     "execution_count": None, "outputs": []}]}
    out = kn.rewrite_install(nb, cell_body=["# custom\n"])
    assert "".join(out["cells"][0]["source"]) == "# custom\n"


def test_rewrite_install_does_not_shadow_its_parameter():
    """A loop variable named `cell` once shadowed the `cell` parameter.

    The symptom was not an exception: it built a dict that referenced itself,
    and json.dumps raised "Circular reference detected" only at write time.
    """
    import _kaggle_notebook as kn

    nb = {"cells": [{"cell_type": "code", "source": ["!pip install x\n"],
                     "execution_count": 1, "outputs": []},
                    {"cell_type": "code", "source": ["print(1)\n"],
                     "execution_count": 1, "outputs": []}]}
    out = kn.rewrite_install(nb)
    json.dumps(out)  # must not raise
    assert len(out["cells"]) == 2
    assert out["cells"][1]["source"] == ["print(1)\n"]


def test_kernel_metadata_satisfies_kaggles_rules():
    """Kaggle validates these before the upload and rejects with a bare message."""
    import build_kaggle  # noqa: F401  (forces the build)

    assert 20 <= len(ds.README) >= 0
    meta_path = ROOT / "kaggle_dataset" / "dataset-metadata.json"
    if not meta_path.is_file():
        pytest.skip("run: python tools/build_kaggle.py")
    meta = json.loads(meta_path.read_text())

    assert 20 <= len(meta["subtitle"]) <= 80, "kaggle wants a 20-80 char subtitle"
    assert 20 <= len(meta["title"]) <= 80, "kaggle wants a 20-80 char title"
    assert meta["id"].count("/") == 1, "id must be owner/slug"
    assert meta["id"].startswith("simonmarc/"), "the owner must be simonmarc"
    assert meta["keywords"], "a dataset with no tags is harder to find"


def test_dataset_keywords_are_lowercase_and_short():
    # kaggle silently drops unrecognised tags and caps how many new categories
    # one upload may create; an 8-item list failed outright
    meta = json.loads((ROOT / "kaggle_dataset" / "dataset-metadata.json").read_text())
    assert len(meta["keywords"]) <= 4
    for kw in meta["keywords"]:
        assert kw == kw.lower(), f"{kw!r} must be lowercase"
        assert kw.strip() == kw


def test_dataset_resources_all_exist():
    out = ROOT / "kaggle_dataset"
    if not (out / "dataset-metadata.json").is_file():
        pytest.skip("run: python tools/build_kaggle.py")
    meta = json.loads((out / "dataset-metadata.json").read_text())
    for res in meta["resources"]:
        assert (out / res["path"]).is_file(), f"{res['path']} listed but missing"


def test_every_copied_file_is_listed_as_a_resource():
    out = ROOT / "kaggle_dataset"
    if not (out / "dataset-metadata.json").is_file():
        pytest.skip("run: python tools/build_kaggle.py")
    meta = json.loads((out / "dataset-metadata.json").read_text())
    listed = {r["path"] for r in meta["resources"]}
    for f in out.iterdir():
        if f.name in ("dataset-metadata.json", "README.md", "LICENSE"):
            continue
        assert f.name in listed, f"{f.name} ships but is undocumented"


def test_no_destructive_payload_leaks_into_the_dataset():
    out = ROOT / "kaggle_dataset" / "payloads.jsonl"
    if not out.is_file():
        pytest.skip("run: python tools/build_kaggle.py")
    blob = out.read_text(encoding="utf-8").lower()
    for bad in ("drop table", "delete from", "xp_cmdshell", "; rm -rf",
                "sleep(", "benchmark(", "/dev/tcp", "nc -e"):
        assert bad not in blob, f"{bad!r} must never ship in a public dataset"


# --- kernel metadata -------------------------------------------------------


def test_kernel_metadata_has_the_required_fields():
    meta = kn.kernel_metadata("simonmarc")
    # without kernel_type the push is rejected outright:
    # "A valid kernel type must be specified in the metadata"
    assert meta["kernel_type"] == "notebook"
    assert meta["language"] == "python"
    assert meta["code_file"] == "hf_demo.ipynb"
    assert meta["id"] == "simonmarc/polyglot-bug-patterns-demo"


def test_kernel_title_resolves_to_the_id():
    # kaggle warns loudly when the slugified title != the id you asked for
    meta = kn.kernel_metadata("simonmarc")
    slug = re.sub(r"[^a-z0-9]+", "-", meta["title"].lower()).strip("-")
    assert slug == meta["id"].split("/", 1)[1], f"{slug!r} != {meta['id']!r}"


def test_kernel_title_and_subtitle_lengths():
    meta = kn.kernel_metadata("simonmarc")
    assert 5 <= len(meta["title"]) <= 100
    assert 20 <= len(meta["subtitle"]) <= 80


def test_kernel_is_public():
    """Kernels are private by default and the CLI has no visibility flag.

    The key is `is_private`, NOT `public`. Writing "public": "true" is
    silently ignored - the push succeeds, the run is COMPLETE, and the page
    still 404s for everyone but the owner. Confirmed by round-tripping the
    metadata: a pulled kernel has `is_private` and no `public` key at all.
    """
    meta = kn.kernel_metadata("simonmarc")
    assert meta["is_private"] is False
    assert "public" not in meta, (
        "'public' is silently ignored; use is_private=False or the kernel "
        "stays private and 404s")


def test_kernel_metadata_survives_a_pull_round_trip():
    """A pulled kernel uses different key names than the ones we send.

    Recorded because it is how both silently-ignored-key bugs were found. The
    round-tripped document is the only honest description of what Kaggle
    actually stores.

    Only the keys we control are asserted. `docker_image`, `machine_shape` and
    `id_no` appear in a pulled kernel but are assigned by the server, so sending
    them is not expected.
    """
    meta = kn.kernel_metadata("simonmarc")
    # keys we must send under Kaggle's own names
    for key in ("is_private", "enable_internet", "kernel_type", "code_file",
                "language", "id", "title"):
        assert key in meta, f"{key} is missing"
    # keys we must NOT send: accepted, ignored, and misleading
    for stale in ("public", "enable_free_internet"):
        assert stale not in meta, (
            f"{stale!r} is silently ignored by Kaggle - it keeps its own default "
            "instead, which is how a private-with-internet kernel happened")


def test_kernel_requests_no_accelerator_and_no_internet():
    # the demo is a local loopback scan: a GPU is wasted quota and internet
    # access is not needed for a self-contained kernel
    meta = kn.kernel_metadata("simonmarc")
    assert meta["enable_gpu"] is False
    assert meta["enable_tpu"] is False
    # enable_internet, NOT enable_free_internet. We sent the latter for several
    # versions and the kernel ran with internet on the whole time, because
    # Kaggle ignored a key it does not know and used its own default of True.
    # Same silently-ignored-key failure as "public" vs "is_private".
    assert meta["enable_internet"] is False
    assert "enable_free_internet" not in meta, \
        "Kaggle does not read this key; it silently kept internet enabled"


def test_kernel_uses_no_pypi_install():
    """The package is not on PyPI. Installing by name fails at runtime."""
    cell = "".join(_install_lines_from_metadata())
    assert "pip install -q polyglot-bug-hunter-x" not in cell
    assert "git+https" not in cell


def _install_lines_from_metadata():
    nb_path = ROOT / "kaggle_kernel" / "hf_demo.ipynb"
    if not nb_path.is_file():
        return [""]
    nb = json.loads(nb_path.read_text())
    for c in nb["cells"]:
        src = "".join(c.get("source", []))
        if "_WHEEL_B64" in src:
            return c["source"]
    return [""]


def test_kernel_inlines_the_wheel_and_it_round_trips():
    """The artifact lives inside the notebook because Kaggle drops extra files.

    Confirmed by the kernel log across three attempts: a source folder arrived
    as "File './package' does not exist", and a plain .whl next to the notebook
    left `glob` empty.
    """
    nb_path = ROOT / "kaggle_kernel" / "hf_demo.ipynb"
    whl = next(iter(sorted((ROOT / "kaggle_kernel").glob("*.whl"))), None)
    if not nb_path.is_file() or whl is None:
        pytest.skip("run: python tools/build_kaggle_kernel.py")

    src = "".join(_install_lines_from_metadata())
    m = re.search(r'_WHEEL_B64 = """\n(.*?)"""', src, re.S)
    assert m, "the wheel base64 block is missing from the install cell"

    decoded = base64.b64decode(m.group(1))
    assert decoded == whl.read_bytes(), "the inlined wheel differs from the real one"
    assert zipfile.is_zipfile(io.BytesIO(decoded)), "inlined payload is not a valid wheel"

    names = zipfile.ZipFile(io.BytesIO(decoded)).namelist()
    assert "polyglot_bug_hunter/__init__.py" in names
    assert "polyglot_bug_hunter/cli.py" in names, "the CLI should ship too"


def test_prepare_keeps_every_code_cell():
    if not (ROOT / "kaggle_kernel" / "hf_demo.ipynb").is_file():
        pytest.skip("run: python tools/build_kaggle_kernel.py")
    nb = json.loads((ROOT / "kaggle_kernel" / "hf_demo.ipynb").read_text())
    original = json.loads((ROOT / "notebooks" / "hf_demo.ipynb").read_text())
    assert len(nb["cells"]) == len(original["cells"]), "a cell was dropped"
    assert sum(1 for c in nb["cells"] if c["cell_type"] == "code") >= 10


def test_kernel_notebook_has_no_stale_outputs():
    if not (ROOT / "kaggle_kernel" / "hf_demo.ipynb").is_file():
        pytest.skip("run: python tools/build_kaggle_kernel.py")
    nb = json.loads((ROOT / "kaggle_kernel" / "hf_demo.ipynb").read_text())
    for c in nb["cells"]:
        if c["cell_type"] == "code":
            assert c.get("outputs") == [], "outputs must be cleared for Kaggle"
            assert c.get("execution_count") is None


def test_kernel_notebook_has_no_host_specific_paths():
    if not (ROOT / "kaggle_kernel" / "hf_demo.ipynb").is_file():
        pytest.skip("run: python tools/build_kaggle_kernel.py")
    src = "\n".join(
        "".join(c.get("source", [])) for c in
        json.loads((ROOT / "kaggle_kernel" / "hf_demo.ipynb").read_text())["cells"]
    )
    # /content and /kaggle/input are jupyter paths that do not exist on Kaggle
    assert "/content/" not in src, "jupyter-native path would break on Kaggle"
    assert "Default Project" not in src, "an absolute local path leaked in"


def test_kernel_description_mentions_the_dataset():
    meta = kn.kernel_metadata("simonmarc")
    assert "kaggle.com/datasets" in meta["description"]
    assert "non-destructive" in meta["description"]


def test_kernel_writes_only_the_notebook_and_metadata(tmp_path, monkeypatch):
    """Extra files in the folder are debris: the notebook writes reports."""
    monkeypatch.setattr(kn, "OUT", tmp_path / "k")
    if not kn.NOTEBOOK.is_file():
        pytest.skip("run: python tools/build_notebook.py")
    (tmp_path / "k").mkdir(parents=True)
    (tmp_path / "k" / "artifacts").mkdir()
    (tmp_path / "k" / "pbhx_canary.png").write_bytes(b"x")
    assert kn.main() == 0
    names = {p.name for p in (tmp_path / "k").iterdir()}
    assert "artifacts" not in names, "stale output dirs must not be pushed"
    assert "pbhx_canary.png" not in names
    assert {"hf_demo.ipynb", "kernel-metadata.json"} <= names
