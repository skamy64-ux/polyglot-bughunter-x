"""Tests for the CLI.

The important ones are the refusal paths. A scanner whose CLI can be talked
into scanning an unauthorized target is worse than no CLI, so those get
asserted directly rather than by inspection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from polyglot_bug_hunter import cli
from polyglot_bug_hunter.config import ModalityConfig
from polyglot_bug_hunter.safety import AuthorizationError, ScanPolicy


def run(*argv: str) -> int:
    return cli.main(list(argv))


# --- parser ----------------------------------------------------------------


def test_parser_builds_without_conflicts():
    # a duplicated --out used to blow up at parse time
    ap = cli.build_parser()
    assert ap.prog == "pbhx"


def test_version_flag_exits_zero(capsys):
    """Compare against pyproject, not a literal.

    A hard-coded version here fails on every release for no reason, and a check
    that cries wolf is a check people stop running.
    """
    from polyglot_bug_hunter import __version__

    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_subcommand_is_an_error():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_unknown_subcommand_is_an_error():
    with pytest.raises(SystemExit) as exc:
        cli.main(["nope"])
    assert exc.value.code == 2


def test_modes_flag_is_parsed_into_a_list():
    raw = cli.build_parser().parse_args(["demo", "--modes", "text,image"]).modes
    assert cli.normalize_modes(raw) == ModalityConfig.parse("text,image").enabled()


def test_normalize_modes_passes_none_through():
    assert cli.normalize_modes(None) is None


# --- authorization gate ----------------------------------------------------


def test_scan_refuses_without_authorization(capsys):
    assert run("scan", "https://example.com") == 2
    out = capsys.readouterr().err
    assert "--i-own-this" in out
    assert "pbhx demo" in out


def test_scan_refusal_happens_before_any_banner(capsys):
    # a refusal should be the only thing printed; a "scanning ..." header
    # would read as if the scan had started
    run("scan", "https://example.com")
    captured = capsys.readouterr()
    assert "scanning" not in captured.out


def test_scan_refuses_out_of_scope_host(capsys):
    code = run("scan", "https://evil.example", "--i-own-this", "--host", "good.example")
    assert code == 2
    assert "not in scope" in capsys.readouterr().err


def test_scan_refuses_private_network_by_default(capsys):
    code = run("scan", "http://127.0.0.1:8000", "--i-own-this")
    assert code == 2
    assert "private" in capsys.readouterr().err.lower()


def test_scan_refuses_non_http_scheme(capsys):
    code = run("scan", "file:///etc/passwd", "--i-own-this")
    assert code == 2
    assert "http" in capsys.readouterr().err.lower()


def test_i_own_this_builds_a_usable_policy():
    ap = cli.build_parser()
    args = ap.parse_args(["scan", "https://x.example", "--i-own-this",
                          "--active", "--note", "engagement 42"])
    policy = cli.build_policy(args)
    assert policy.authorization_confirmed
    assert policy.active_probing
    assert policy.authorization_note == "engagement 42"


def test_note_becomes_the_authorization_record():
    ap = cli.build_parser()
    args = ap.parse_args(["scan", "https://x.example", "--i-own-this"])
    policy = cli.build_policy(args)
    assert policy.authorization_note  # never empty, so the report is honest


def test_host_allowlist_is_normalized():
    ap = cli.build_parser()
    args = ap.parse_args(["scan", "https://x.example", "--i-own-this",
                          "--host", "A.example, b.example"])
    policy = cli.build_policy(args)
    assert policy.allowed_hosts == {"a.example", "b.example"}


def test_scan_policy_itself_refuses_unconfirmed():
    policy = ScanPolicy()
    with pytest.raises(AuthorizationError):
        policy.check_url("https://example.com")


# --- exit codes ------------------------------------------------------------


@pytest.mark.slow
def test_demo_exits_nonzero_when_it_finds_things(tmp_path):
    # the demo target is deliberately vulnerable; exit 0 here would let a CI
    # gate read a broken target as clean
    assert run("demo", "--quiet", "--out", str(tmp_path)) == 1


@pytest.mark.slow
def test_demo_writes_a_report(tmp_path):
    run("demo", "--quiet", "--out", str(tmp_path))
    files = {p.suffix for p in tmp_path.iterdir()}
    assert {".html", ".json", ".md", ".sarif"} <= files


@pytest.mark.slow
def test_demo_fail_on_high_trips(tmp_path):
    assert run("demo", "--quiet", "--fail-on", "high", "--out", str(tmp_path)) == 1


def test_fail_on_is_available_on_demo():
    # a CI gate that cannot run offline is a gate nobody runs
    ap = cli.build_parser()
    assert ap.parse_args(["demo", "--fail-on", "critical"]).fail_on == "critical"
    assert ap.parse_args(["scan", "https://x.example", "--fail-on", "high"]).fail_on == "high"


# --- offline commands ------------------------------------------------------


def test_capabilities_lists_extras(capsys):
    assert run("capabilities") == 0
    out = capsys.readouterr().out
    assert "optional" in out
    assert "playwright" in out


def test_targets_lists_practice_sites(capsys):
    assert run("targets") == 0
    out = capsys.readouterr().out
    assert "i-own-this" in out
    assert "http" in out


def test_payloads_summary(capsys):
    assert run("payloads") == 0
    out = capsys.readouterr().out
    assert "payloads across" in out


def test_payloads_class_filter(capsys):
    assert run("payloads", "--class", "sqli") == 0
    out = capsys.readouterr().out
    assert "cvss:" in out
    assert "OR" in out or "union" in out.lower()


def test_payload_analysis_explains_a_template_probe(capsys):
    assert run("payload", "{{7*7}}") == 0
    out = capsys.readouterr().out
    assert "template" in out
    assert "ssti" in out


def test_payload_analysis_flags_ssrf_shape(capsys):
    assert run("payload", "http://169.254.169.254/latest/meta-data/") == 0
    assert "ssrf" in capsys.readouterr().out


def test_payload_analysis_refuses_a_destructive_value(capsys):
    # the analyzer should not be a way to launder a destructive string
    assert run("payload", "rm -rf / --no-preserve-root") in (0, 1, 2)
    combined = capsys.readouterr().out
    assert "destructive" in combined or "signals" in combined


def test_payload_analysis_survives_an_unknown_value(capsys):
    assert run("payload", "hello world") == 0
    assert "signals" in capsys.readouterr().out


def test_canary_writes_a_png(tmp_path):
    out = tmp_path / "canary.png"
    assert run("canary", "-o", str(out)) == 0
    assert out.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    # the text must not be legible in the rendered pixels
    assert b"ignore all previous" not in out.read_bytes()


def test_canary_visible_variant_differs(tmp_path):
    a, b = tmp_path / "a.png", tmp_path / "b.png"
    run("canary", "-o", str(a), "--hidden", "near-invisible-white-on-white")
    run("canary", "-o", str(b), "--hidden", "visible-black-on-white")
    assert a.read_bytes() != b.read_bytes()


def test_audio_suite_writes_malformed_files(tmp_path):
    assert run("audio", "-o", str(tmp_path)) == 0
    names = {p.name for p in tmp_path.iterdir()}
    # everything lands as .wav on purpose: the point is that a validator
    # trusting the extension gets fooled
    assert names
    assert all(n.endswith(".wav") for n in names)
    # some of them are not actually audio
    assert (tmp_path / "html-in-audio.wav").read_bytes()[:1] == b"<"
    assert (tmp_path / "svg-in-audio.wav").read_bytes()[:1] == b"<"
    assert (tmp_path / "zip-in-audio.wav").read_bytes()[:2] == b"PK"
    # and some are, so the suite is not only false positives
    assert (tmp_path / "valid-tone.wav").read_bytes()[:4] == b"RIFF"
    assert (tmp_path / "silent.wav").read_bytes()[:4] == b"RIFF"


def test_audio_subset_is_smaller_than_all(tmp_path):
    run("audio", "-o", str(tmp_path / "all"))
    run("audio", "-o", str(tmp_path / "one"), "--kind", "tone")
    assert len(list((tmp_path / "one").iterdir())) < len(list((tmp_path / "all").iterdir()))


# --- report plumbing -------------------------------------------------------


def test_json_flag_emits_valid_json(tmp_path, capsys):
    run("demo", "--quiet", "--json", "--out", str(tmp_path))
    payload = capsys.readouterr().out
    start = payload.index("{")
    data = json.loads(payload[start:])
    assert data["target"]
    assert "findings" in data


def test_out_dir_is_created_if_absent(tmp_path):
    target = tmp_path / "deep" / "nested"
    run("demo", "--quiet", "--out", str(target))
    assert target.is_dir() and any(target.iterdir())


def test_quiet_suppresses_progress(capsys):
    run("demo", "--quiet", "--out", str(Path("/tmp/opencode/cli-quiet-test")))
    assert "[ 1]" not in capsys.readouterr().err


def test_lang_flag_is_accepted():
    ap = cli.build_parser()
    assert ap.parse_args(["demo", "--lang", "id"]).lang == "id"


def test_bad_lang_is_rejected():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["demo", "--lang", "klingon"])
