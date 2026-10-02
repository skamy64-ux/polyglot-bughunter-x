"""Tests for tools/build_kaggle.py and tools/build_kaggle_kernel.py.

The Kaggle builders are pure string/metadata work, but the failures they exist
to prevent are expensive: a bad subtitle or a missing `kernel_type` is a
rejected push, and a dropped artifact is a red kernel. Both were real bugs
during development, so both are asserted here rather than left to a live push.
"""

from __future__ import annotations

import importlib.util
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


def test_dataset_notebook_falls_back_to_a_vcs_install():
    """A missing wheel is no longer fatal: the GitHub tag is the real answer.

    The wheel in the dataset is the offline path. Without it the notebook
    installs from the repo, which is what made the base64 fallback unnecessary
    in the first place.
    """
    nb_path = ROOT / "kaggle_dataset" / "hf_demo.ipynb"
    if not nb_path.is_file():
        pytest.skip("run: python tools/build_kaggle.py")
    src = _notebook_source(nb_path)
    assert "git+https://github.com/" in src
    assert "skamy64-ux/polyglot-bughunter-x@" in src
    assert "_wheel = _VCS" in src or "_wheel = _VCS\n" in src


def test_neither_notebook_carries_a_wheel_anymore():
    """Both used to inline a 110 KB wheel. The repo exists; install from it.

    Asserted because the base64 came back once already: a notebook that
    inlines a build artifact cannot be reviewed, diffed, or read, and a
    truncated paste surfaces as a pip error with no useful context.
    """
    for rel in ("kaggle_dataset/hf_demo.ipynb", "kaggle_kernel/hf_demo.ipynb"):
        nb = ROOT / rel
        if not nb.is_file():
            pytest.skip(f"run the builder for {rel}")
        src = _notebook_source(nb)
        assert "_WHEEL_B64" not in src, f"{rel} still inlines a wheel"
        assert nb.stat().st_size < 40_000, (
            f"{rel} is {nb.stat().st_size // 1024} KB, which suggests an "
            f"inlined artifact crept back in")


def test_both_notebooks_install_the_same_pinned_ref():
    # The existence check has to come before the read. `if not k` looks like a
    # guard but _notebook_source() has already raised by the time it is
    # evaluated, so on a clean tree this was a FileNotFoundError rather than a
    # skip. Caught by the publish workflow's first run, which runs the gate on a
    # fresh checkout with none of the build folders present.
    k_nb = ROOT / "kaggle_kernel" / "hf_demo.ipynb"
    d_nb = ROOT / "kaggle_dataset" / "hf_demo.ipynb"
    if not (k_nb.is_file() and d_nb.is_file()):
        pytest.skip("run both builders: tools/build_kaggle.py and "
                    "tools/build_kaggle_kernel.py")
    k = _notebook_source(k_nb)
    d = _notebook_source(d_nb)
    ref = re.search(r"github\.com/skamy64-ux/polyglot-bughunter-x@(\S+?)['\"]", k)
    assert ref, "the kernel does not install from a pinned ref"
    assert ref.group(1) in d, \
        f"the kernel installs {ref.group(1)} but the dataset does not"


def test_the_pinned_ref_is_a_tag_not_a_branch():
    """A branch ref means a published notebook silently changes behaviour."""
    import _kaggle_notebook as kn

    assert kn.REPO_TAG.startswith("v"), "the ref must be a version tag"
    assert kn.REPO_TAG in kn.VCS_URL
    for bad in ("@main", "@master", "@HEAD"):
        assert bad not in kn.VCS_URL, f"{bad} moves; the notebook would too"


def test_the_pinned_tag_actually_exists_on_github():
    """An installer pointing at a tag that was never pushed breaks at read time.

    Checked over the network because nothing local can know. Skipped when
    offline rather than failed, so the suite stays usable on a plane.

    GET, not HEAD, and retried. This test failed intermittently for a whole
    afternoon on a tag that was definitely there, for two reasons at once:

    - GitHub does not implement HEAD on release pages, so the request can
      answer 404 or 405 for a release that exists. tools/check_links.py hit the
      same wall and it cost real debugging time there.
    - a tag pushed moments earlier is still being indexed, and the page 404s
      while that happens. Measured here: the same suite passed 422/422 four
      consecutive times and failed once immediately after a force-push.

    A check that fails at random on a correct tree trains people to re-run
    until it is green, which is the same as having no check. A 5xx or a timeout
    is the host declining to answer, not a verdict on the tag, so it is
    retried and then skipped rather than reported.
    """
    import time
    import urllib.error
    import urllib.request

    import _kaggle_notebook as kn

    url = f"https://github.com/{kn.GITHUB_OWNER}/{kn.REPO}/releases/tag/{kn.REPO_TAG}"
    last = ""
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0 Safari/537.36",
                "Accept": "text/html,*/*",
            })
            with urllib.request.urlopen(req, timeout=25) as r:
                if r.status == 200:
                    return
                last = str(r.status)
        except urllib.error.HTTPError as e:
            if e.code == 404 and attempt == 0:
                # one retry before believing it: a just-pushed tag 404s while
                # GitHub indexes it
                last = "404"
            elif e.code in (429, 500, 502, 503, 504):
                last = str(e.code)
            else:
                pytest.fail(f"{url} returned {e.code}. The notebooks install "
                            f"from this ref; push the tag before publishing.")
        except Exception as e:
            last = type(e).__name__
        time.sleep(3 * (attempt + 1))

    pytest.skip(f"github did not answer ({last}); not a verdict on the tag")


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
    meta_path = ROOT / "kaggle_dataset" / "dataset-metadata.json"
    if not meta_path.is_file():
        # CI checks out a clean tree; the build folders are gitignored, so this
        # has to skip rather than blow up on a missing file. Caught by the first
        # CI run, where this was the only failure on 3.11, 3.12 and 3.13.
        pytest.skip("run: python tools/build_kaggle.py")
    meta = json.loads(meta_path.read_text())
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


def test_kernel_is_offline_and_therefore_carries_a_wheel_path():
    """enable_internet off means pip cannot reach a URL. Those are one fact.

    Turning the network on would have been the easy fix for `git clone` exiting
    128, and the wrong one: the demo is a loopback scan that needs no network at
    runtime, and a security scanner is the last thing that should quietly
    acquire one. The wheel is attached as a dataset instead, which Kaggle
    mounts without a network.
    """
    meta = kn.kernel_metadata("simonmarc")
    assert meta["enable_internet"] is False, (
        "the kernel has no reason for network access; if that changes, say why "
        "in the changelog rather than flipping this")
    assert meta["dataset_sources"] == ["simonmarc/polyglot-bug-patterns"], (
        "the wheel has to come from somewhere, and the attached dataset is how "
        "it arrives without a network")
    assert meta["competition_data"] == []


def test_kernel_install_cell_has_a_file_path_not_only_a_url():
    """A URL-only cell fails with git clone exit 128 under enable_internet off.

    Found by pushing it, which is the only way this was going to be found: it
    works perfectly on any developer machine that has a network.
    """
    nb = ROOT / "kaggle_kernel" / "hf_demo.ipynb"
    if not nb.is_file():
        pytest.skip("run: python tools/build_kaggle_kernel.py")
    src = _notebook_source(nb)
    assert "*.whl" in src, "no wheel glob means no offline install path"
    assert "kaggle/input" in src, "the glob must look where Kaggle mounts inputs"


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


# --- trove classifiers -----------------------------------------------------
# "Natural Language :: Chinese" is not a PyPI classifier. PyPI rejects the
# entire upload for it with a 400, and a version cannot be reused after a
# rejected release, so this is checked before every publish.


def _classifier_checker():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_classifiers", ROOT / "tools" / "check_classifiers.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_classifier_parser_handles_multi_word_first_segment():
    """The first segment is often several words: "Development Status".

    A pattern that assumes one word matches nothing and reports an empty list,
    which looks exactly like a pyproject with no classifiers in it.
    """
    cc = _classifier_checker()
    found = cc.declared()
    assert found, "the parser found no classifiers at all"
    assert "Development Status :: 4 - Beta" in found
    assert "Intended Audience :: Developers" in found


def test_classifier_parser_handles_parentheses():
    """Some valid classifiers contain parentheses.

    "Natural Language :: Chinese (Simplified)" is the one PyPI requires in
    place of the bare "Chinese". A character set without () drops it silently.
    """
    cc = _classifier_checker()
    found = cc.declared()
    assert any("(" in c for c in found), "parenthesised classifiers were dropped"


def test_every_declared_classifier_matches_its_own_shape():
    cc = _classifier_checker()
    for c in cc.declared():
        assert "::" in c, f"{c!r} is not a classifier"
        assert not c.endswith("::"), f"{c!r} has a trailing separator"


def test_the_rejected_classifier_is_not_in_pyproject():
    """The exact string that caused a 400 on the first upload attempt."""
    txt = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"Natural Language :: Chinese",' not in txt, (
        "PyPI rejects this exact string; it wants Chinese (Simplified)")
    assert '"Natural Language :: Chinese (Simplified)",' in txt


def test_classifier_check_is_wired_into_the_release_gate():
    """A check nobody runs is not a check."""
    src = (ROOT / "tools" / "release.py").read_text()
    assert "check_classifiers.py" in src
    wf = (ROOT / ".github" / "workflows" / "publish.yml").read_text()
    assert "check_classifiers.py" in wf
