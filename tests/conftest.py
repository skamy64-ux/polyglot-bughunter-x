"""Shared fixtures. One demo server for the whole session - starting an HTTP
server per test would be slower than the tests themselves.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from polyglot_bug_hunter.config import ScanConfig  # noqa: E402
from polyglot_bug_hunter.demo_target import DemoServer  # noqa: E402
from polyglot_bug_hunter.hunter import Hunter  # noqa: E402
from polyglot_bug_hunter.safety import ScanPolicy  # noqa: E402


@pytest.fixture(scope="session")
def demo_server():
    with DemoServer() as srv:
        yield srv


@pytest.fixture(scope="session")
def permissive_policy():
    """A policy that allows localhost, because the target is our own."""
    return ScanPolicy(
        authorization_confirmed=True,
        authorization_note="pytest, our own in-process demo target",
        active_probing=True,
        allow_private_network=True,
        allow_state_changing_methods=True,
        rate_per_minute=6000,
        max_requests=100_000,
    )


@pytest.fixture(scope="session")
def http(permissive_policy):
    from polyglot_bug_hunter.net import Http
    return Http(permissive_policy, ScanConfig())


@pytest.fixture(scope="session")
def report():
    """One full scan of the demo target, shared by the report tests."""
    return Hunter.demo(modes=["text", "passive", "image", "audio"])


@pytest.fixture
def hunter(permissive_policy):
    return Hunter(
        policy=permissive_policy,
        config=ScanConfig(max_pages=6, max_depth=2, screenshot=False),
        modes=["text", "passive"],
    )
