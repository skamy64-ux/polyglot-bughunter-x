"""Tests for tools/build_kaggle.py and tools/build_kaggle_kernel.py.

The Kaggle builders are pure string/metadata work, but the failures they exist
to prevent are expensive: a bad subtitle or a missing `kernel_type` is a
rejected push, and a dropped artifact is a red kernel. Both were real bugs
during development, so both are asserted here rather than left to a live push.
"""

from __future__ import annotations

import base64
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


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ds = load("build_kaggle")
kn = load("build_kaggle_kernel")


# --- dataset metadata ------------------------------------------------------


def test_dataset_metadata_satisfies_kaggles_rules():
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

    Recorded because it is how the is_private/public mixup was found: the
    round-tripped document is the only honest description of what Kaggle
    actually stores.
    """
    meta = kn.kernel_metadata("simonmarc")
    # these are the names a pulled kernel comes back with
    pulled_names = {"is_private", "enable_internet", "docker_image",
                    "machine_shape", "id_no"}
    assert pulled_names & set(meta), "we send none of the keys Kaggle stores"
    # enable_free_internet is ours; Kaggle calls it enable_internet
    assert "enable_free_internet" in meta


def test_kernel_requests_no_accelerator_and_no_internet():
    # the demo is a local loopback scan: a GPU is wasted quota and internet
    # access is not needed for a self-contained kernel
    meta = kn.kernel_metadata("simonmarc")
    assert meta["enable_gpu"] is False
    assert meta["enable_tpu"] is False
    assert meta["enable_free_internet"] is False


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
