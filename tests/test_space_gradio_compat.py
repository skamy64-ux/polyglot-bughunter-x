"""Tests for the Gradio Space's compatibility shim.

Gradio 6 removed two arguments this file uses: `show_copy_button` on Textbox,
and `theme`/`css` on the Blocks constructor. Dependabot opened a PR widening
the pin to `<7` and it would have shipped a Space that cannot start, because
the failure is a TypeError at import time on a machine nobody tested.

The rule here: anything the app passes to Gradio must be accepted by the
Gradio that is actually installed, on whatever major version that is. The
tests assert against the live signature rather than a list of versions, so a
Gradio 7 breaks them instead of the Space.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "hf_space" / "app.py"

gr = pytest.importorskip("gradio")

MAJOR = int(str(gr.__version__).split(".")[0])


def _app_module():
    """Import the Space app without launching it."""
    os.environ["PBHX_NO_LAUNCH"] = "1"
    sys.path.insert(0, str(ROOT / "src"))
    try:
        spec = importlib.util.spec_from_file_location("hf_space_app", APP)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        os.environ.pop("PBHX_NO_LAUNCH", None)


def test_app_imports_on_the_installed_gradio():
    mod = _app_module()
    assert mod.ui is not None
    assert len(mod.ui.blocks) > 20, "the UI looks empty"


def test_show_copy_button_is_never_passed_directly_to_textbox():
    """Gradio 6 removed it; calling gr.Textbox(show_copy_button=...) raises.

    The app must go through the _tb() shim. A bare gr.Textbox(...,
    show_copy_button=...) anywhere is a latent TypeError.
    """
    src = APP.read_text(encoding="utf-8")
    # strip comments first: the compatibility note above the shim mentions
    # gr.Textbox(show_copy_button=...) in prose, and matching that would fail
    # every run for a line that is not code.
    code = "\n".join(
        ln for ln in src.splitlines() if not ln.lstrip().startswith("#")
    )
    offenders = [m.start() for m in re.finditer(r"gr\.Textbox\(", code)]
    for start in offenders:
        # look at the full call, not just the opening paren
        depth, i = 0, start + len("gr.Textbox(") - 1
        while i < len(code):
            if code[i] == "(":
                depth += 1
            elif code[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        call = code[start:i]
        if "show_copy_button" in call:
            line = src[:start].count("\n") + 1  # report against the real file
            pytest.fail(
                f"hf_space/app.py:{line} passes show_copy_button straight to "
                f"gr.Textbox. Gradio 6 removed it. Use the _tb() shim.")


def test_tb_shim_drops_removed_kwargs_on_gradio_6():
    if MAJOR < 6:
        pytest.skip(f"gradio {gr.__version__} still accepts show_copy_button")
    mod = _app_module()
    box = mod._tb(label="x", show_copy_button=True)
    assert box is not None, "_tb must not raise on a removed kwarg"


def test_tb_shim_keeps_the_kwarg_on_gradio_5():
    if MAJOR >= 6:
        pytest.skip("gradio 6+ removed show_copy_button; nothing to preserve")
    mod = _app_module()
    assert mod._tb(label="x", show_copy_button=True) is not None


def test_theme_and_css_are_routed_to_the_right_place():
    """Gradio 6 moved theme/css from the Blocks constructor to launch().

    Passing them to Blocks on 6 is not an error, it is a warning and the
    stylesheet is dropped - the Space loses all its CSS and still starts, which
    is worse than a crash because nothing fails.
    """
    mod = _app_module()
    blocks_params = inspect.signature(gr.Blocks.__init__).parameters
    launch_params = inspect.signature(gr.Blocks.launch).parameters

    if MAJOR >= 6:
        assert "theme" not in blocks_params, "test is stale: gradio 6 took theme back"
        assert "css" not in blocks_params
        assert mod._BLOCKS_KWARGS == {}, (
            "on Gradio 6 the constructor ignores theme/css and the CSS is lost")
        assert "theme" in mod._LAUNCH_STYLE and "css" in mod._LAUNCH_STYLE, (
            "on Gradio 6 the style must be handed to launch() or the Space "
            "renders unstyled with no error to explain why")
        assert "css" in launch_params or MAJOR >= 6
    else:
        assert "theme" in blocks_params
        assert mod._BLOCKS_KWARGS.get("css"), "on Gradio 5 css belongs on Blocks"
        assert mod._LAUNCH_STYLE == {}


def test_the_css_is_actually_defined():
    mod = _app_module()
    css = mod._BLOCKS_KWARGS.get("css") or mod._LAUNCH_STYLE.get("css")
    assert css, "CSS_FULL resolved to nothing; the Space would render unstyled"
    assert "{" in css and "}" in css, "CSS_FULL does not look like CSS"
    assert len(css) > 200, "CSS_FULL is suspiciously small"


def test_all_four_tabs_are_present():
    src = APP.read_text(encoding="utf-8")
    for label in ("Scan", "Multimodal", "Report", "About"):
        assert label in src, f"the {label!r} tab is missing"


def test_requirements_pin_is_not_narrower_than_the_tested_range():
    """The pin and the compatibility shim have to agree.

    If the shim is removed the pin must go back to `<6`; if the pin says `<6`
    the shim is dead code nobody is exercising. Either state is fine, having
    them disagree is not.
    """
    for rel in ("requirements.txt", "hf_space/requirements.txt"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        m = re.search(r"gradio>=([\d.]+),<(\d+)", text)
        assert m, f"{rel} does not pin gradio with a range"
        upper = int(m.group(2))
        assert upper >= 6, (
            f"{rel} still pins gradio <6 but the app now carries a Gradio 6 "
            f"shim. Either widen the pin or drop the shim - do not leave both "
            f"believing the other is handling it.")


def test_cli_serve_reports_a_missing_gradio_helpfully():
    """`pbhx serve` on a machine without gradio must say what to install."""
    from polyglot_bug_hunter import cli

    src = inspect.getsource(cli.cmd_serve)
    assert "pip install" in src, "the missing-gradio path must name the fix"
    assert "gradio" in src
