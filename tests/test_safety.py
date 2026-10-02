"""The safety gates. If any of these fail, the tests are wrong, not the code -
and that direction matters, because these gates are the reason this tool is
defensible.
"""

from __future__ import annotations

import socket

import pytest

from polyglot_bug_hunter.net import replace_param
from polyglot_bug_hunter.safety import (
    AuthorizationError,
    RateLimiter,
    ScanPolicy,
    is_forbidden_payload,
    resolve_and_classify,
    sanitize_payloads,
)


class TestAuthorizationGate:
    def test_no_auth_no_bytes(self):
        with pytest.raises(AuthorizationError, match="authorization"):
            ScanPolicy().check_url("https://example.com")

    def test_note_is_optional_but_authorization_is_not(self):
        p = ScanPolicy(authorization_confirmed=True)
        p.require_authorization()  # must not raise

    def test_private_ranges_refused_by_default(self, monkeypatch):
        # don't hit DNS in a unit test - stub the resolver
        import socket

        def fake(host, *a, **k):
            if host == "rebind.example":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]
            raise socket.gaierror("nope")

        monkeypatch.setattr(socket, "getaddrinfo", fake)
        p = ScanPolicy(authorization_confirmed=True)
        with pytest.raises(AuthorizationError, match="link-local"):
            p.check_url("http://rebind.example/")

    @pytest.mark.parametrize(
        "url,why",
        [
            ("file:///etc/passwd", "only speaks http"),
            ("gopher://127.0.0.1:11211/_x", "only speaks http"),
            ("javascript:alert(1)", "only speaks http"),
            ("ftp://example.com", "only speaks http"),
            ("example.com", "full http"),
        ],
    )
    def test_non_http_schemes_refused(self, url, why):
        p = ScanPolicy(authorization_confirmed=True)
        with pytest.raises(AuthorizationError, match=why):
            p.check_url(url)

    def test_host_allowlist_is_enforced(self, monkeypatch):
        import socket
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
        p = ScanPolicy(authorization_confirmed=True, allowed_hosts={"example.com"})
        p.check_url("https://example.com/ok")
        with pytest.raises(AuthorizationError, match="not in scope"):
            p.check_url("https://evil.test/")

    def test_state_changing_methods_need_consent(self):
        p = ScanPolicy(authorization_confirmed=True)
        p.check_method("GET")
        with pytest.raises(AuthorizationError, match="changes state"):
            p.check_method("POST")
        permissive = ScanPolicy(authorization_confirmed=True,
                                allow_state_changing_methods=True)
        permissive.check_method("DELETE")


class TestPayloadGate:
    @pytest.mark.parametrize("bad", [
        "'; DROP TABLE users; --",
        "1 UNION SELECT * FROM x; DELETE FROM accounts",
        "1; system('id')",
        "1; sleep(10)",
        "'; WAITFOR DELAY '0:0:5'",
        "a; cat /etc/passwd | xargs rm -rf /",
        "xp_cmdshell 'dir'",
    ])
    def test_destructive_payloads_blocked(self, bad):
        assert is_forbidden_payload(bad) is not None

    @pytest.mark.parametrize("good", [
        "' OR 1=1 -- ",
        "{{7*7}}",
        "PBHX7reflect",
        "..%2f..%2fetc%2fpasswd",
        "${7*7}",
        "'; return true; //",
    ])
    def test_detection_payloads_allowed(self, good):
        assert is_forbidden_payload(good) is None

    def test_every_shipped_payload_is_safe(self):
        from polyglot_bug_hunter import payloads
        for _, p in payloads.iter_all():
            assert is_forbidden_payload(p.value) is None, (
                f"payload {p.label} would be blocked by our own gate")

    def test_sanitize_splits_cleanly(self):
        good, bad = sanitize_payloads(["{{7*7}}", "1; sleep(5)"])
        assert good == ["{{7*7}}"]
        assert len(bad) == 1 and "sleep" in bad[0][1]


class TestRateLimit:
    def test_budget_is_hard(self):
        p = ScanPolicy(authorization_confirmed=True, max_requests=3)
        for _ in range(3):
            p.throttle()
        with pytest.raises(AuthorizationError, match="budget"):
            p.throttle()
        assert p.requests_sent == 3

    def test_limiter_paces_requests(self):
        import time
        lim = RateLimiter(per_minute=600, burst=2)  # 10/s
        lim.take()
        lim.take()
        t0 = time.perf_counter()
        lim.take()
        assert time.perf_counter() - t0 > 0.05, "third token should have waited"

    def test_report_header_states_the_rules(self):
        p = ScanPolicy(authorization_confirmed=True, authorization_note="unit test",
                       active_probing=True)
        block = p.header_block()
        assert "AUTHORIZED USE ONLY" in block
        assert "unit test" in block
        assert "active probing" in block


class TestIPClassification:
    def test_cloud_metadata_is_link_local(self):
        ok, blocked = resolve_and_classify("169.254.169.254")
        assert blocked and "link-local" in blocked[0][1]

    def test_cgnat_blocked(self):
        from polyglot_bug_hunter.safety import _is_blocked_ip
        assert _is_blocked_ip("100.64.0.1")[0] is True
        assert _is_blocked_ip("8.8.8.8")[0] is False

    @pytest.mark.parametrize("ip,blocked", [
        ("127.0.0.1", True), ("10.1.2.3", True), ("192.168.1.1", True),
        ("172.16.0.1", True), ("169.254.1.1", True), ("0.0.0.0", True),
        ("224.0.0.1", True), ("1.1.1.1", False), ("93.184.216.34", False),
    ])
    def test_ranges(self, ip, blocked):
        from polyglot_bug_hunter.safety import _is_blocked_ip
        assert _is_blocked_ip(ip)[0] is blocked


class TestReplaceParam:
    """This function is load-bearing. If it regresses, every differential test
    silently reports 'clean' and the tool looks like it found nothing."""

    @pytest.mark.parametrize("url,param,value,expected", [
        ("http://x/p?id=1", "id", "9", "http://x/p?id=9"),
        ("http://x/p?a=1&id=1&b=2", "id", "9", "http://x/p?a=1&id=9&b=2"),
        ("http://x/p", "id", "9", "http://x/p?id=9"),
        ("http://x/p?id=1", "other", "9", "http://x/p?id=1&other=9"),
        ("http://x/p?id=", "id", "", "http://x/p?id="),
        ("http://x/p?a=1#frag", "a", "2", "http://x/p?a=2#frag"),
    ])
    def test_no_duplicate_keys(self, url, param, value, expected):
        out = replace_param(url, param, value)
        assert out == expected
        key = out.split("?", 1)[1].split("=", 1)[0]
        assert out.count(f"{key}=") == 1, "the parameter must appear exactly once"

    def test_servers_honour_the_first_value(self, demo_server, http):
        """Reproduces the original bug: ?id=1&id=2 is seen as id=1."""
        url = f"{demo_server.url.rstrip('/')}/customer"
        assert "id=2" in replace_param(url + "?id=1", "id", "2")
        r = http.get(url + "?id=1&id=2")
        assert "alice" in r.body, "demo server honoured the first id, as expected"
        r2 = http.get(replace_param(url + "?id=1", "id", "2"))
        assert "bob" in r2.body, "replace_param must leave exactly one id"


class TestResolverHardening:
    """If we cannot prove an address is public, we must treat it as private."""

    @pytest.mark.parametrize("exc", [
        socket.gaierror("no such host"),
        PermissionError("sandboxed by the runtime"),
        RuntimeError("host resolver exploded"),
    ])
    def test_any_resolver_failure_is_an_auth_error(self, monkeypatch, exc):
        def boom(*a, **k):
            raise exc
        monkeypatch.setattr(socket, "getaddrinfo", boom)
        with pytest.raises(AuthorizationError):
            ScanPolicy(authorization_confirmed=True).check_url("https://whatever.test/")

    def test_unresolvable_ip_literal_is_refused(self):
        p = ScanPolicy(authorization_confirmed=True)
        with pytest.raises(AuthorizationError):
            p.check_url("http://999.999.999.999/")
