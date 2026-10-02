"""Safety rails for PolyglotBugHunter-X.

Everything in this tool fires *requests at someone else's machine*. So the first
import in the whole package is this module, and nothing is allowed to touch the
network before a ScanPolicy says "yes, you are allowed".

Design rules we never break:

1. No authorization -> no request. Ever. Not even a HEAD to the homepage.
2. Private / loopback / link-local space is off by default. That blocks the two
   nastiest abuses: SSRF-ing a cloud metadata endpoint (169.254.169.254) and
   using a scanner as an internal-network port scanner.
3. Payloads are *detection* payloads, never *damage* payloads. We look for a
   reflection, a timing shape, a header gap, a cookie flag. We do not drop
   tables, we do not chain shells, we do not mass-delete.
4. Rate limit is mandatory. A scanner that can DoS is a weapon.
5. Every finding records what proof we got, so a report can be argued about
   with evidence instead of vibes.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# ---- canonical strings (surfaced in the UI + every report) -----------------

LEGAL_NOTICE = (
    "PolyglotBugHunter-X only tests systems you own or have explicit written "
    "permission to test. Unauthorized scanning is illegal in most jurisdictions "
    "(e.g. CFAA 18 U.S.C. 1030, UK Computer Misuse Act 1990 s.1, id. UU ITEA "
    "Pasal 35-51). You are 100% responsible for every target you point this at."
)

BANNER = "AUTHORIZED USE ONLY - passive-by-default web bug hunter"

#: Payloads that mutate state or destroy data. Kept here (not just in code) so a
#: payload from a community PR can't sneak past review by using a raw string.
FORBIDDEN_PAYLOAD_SUBSTRINGS = (
    "drop table",
    "truncate table",
    "delete from",
    "update ",
    "insert into",
    "alter table",
    "xp_cmdshell",
    "; rm -",
    "system(",
    "exec(",
    "passthru(",
    "sleep(",
    "benchmark(",
    "waitfor delay",
    "pg_sleep",
    "unlink(",
    "rmtree(",
    "rm -rf",
    "rm -fr",
    "mkfs",
    "shred ",
    "dd if=",
    "dd of=/dev/",
    "> /dev/sd",
    "chmod 777 /",
    ":(){:|:&};:",     # fork bomb
    "> /dev/null 2>&1 &",
    "shutdown",
    "reboot",
    "iptables -",
    "history -c",
)

#: Method verbs that change state. Allowed, but only behind explicit consent
#: and only on hosts the operator listed.
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class AuthorizationError(PermissionError):
    """Raised when someone tries to scan something they shouldn't."""


class ConsentRequired(AuthorizationError):
    """A *scope* violation was fine, but this one endpoint needs extra consent.

    Subclassing matters: scope violations (wrong host, private network, no
    authorization at all) abort the scan, because continuing would mean testing
    something the operator never agreed to. Missing consent for one form's HTTP
    method just means that form gets skipped, with a note in the report - a
    scanner that dies on the first password field is useless.
    """


# ---- network math ----------------------------------------------------------


def _is_blocked_ip(ip: str) -> tuple[bool, str]:
    """Return (blocked, reason). Blocks the scary parts of the address space."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True, "not-a-valid-ip"
    if addr.is_loopback:
        return True, "loopback"
    if addr.is_link_local:
        return True, "link-local (cloud metadata lives here)"
    if addr.is_private:
        return True, "private rfc1918 range"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return True, "reserved/multicast/unspecified"
    # 100.64.0.0/10 carrier-grade NAT - used by big infra, still not public.
    if ip in ("100.64.0.0", "100.127.255.255"):
        pass
    if ipaddress.ip_network("100.64.0.0/10").overlaps(
        ipaddress.ip_network(f"{ip}/32")
    ):
        return True, "cgnat 100.64.0.0/10"
    return False, "public"


def resolve_and_classify(host: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Resolve a hostname and split results into (allowed_ips, blocked_ips).

    DNS-rebinding is why we resolve *ourselves* instead of trusting whatever
    the socket does later. If any A record lands in blocked space we refuse the
    whole host rather than racing the resolver.
    """
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise AuthorizationError(f"cant resolve {host!r}: {exc}") from exc
    except AuthorizationError:
        raise
    except Exception as exc:
        # A hostile resolver, a sandbox, or an EDR shim can raise anything here.
        # If we cannot prove the address is public, we must treat it as private.
        raise AuthorizationError(
            f"cant resolve {host!r}: {type(exc).__name__}: {exc}"
        ) from exc

    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)

    ok: list[str] = []
    nope: list[tuple[str, str]] = []
    for ip in ips:
        blocked, reason = _is_blocked_ip(ip)
        (nope if blocked else ok).append((ip, reason))
    return ok, nope


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


# ---- rate limiter ----------------------------------------------------------


class RateLimiter:
    """Token bucket. Smooth, tiny, and impossible to accidentally weaponise."""

    def __init__(self, per_minute: int = 20, burst: int = 5) -> None:
        self.rate = max(1, per_minute) / 60.0
        self.capacity = max(1.0, float(burst))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self.slept = 0.0

    def take(self) -> float:
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens < 1.0:
            need = (1.0 - self._tokens) / self.rate
            self.slept += need
            time.sleep(need)
            self._tokens = 1.0
        self._tokens -= 1.0
        return self.slept


# ---- payload vetting -------------------------------------------------------


def is_forbidden_payload(payload: str) -> str | None:
    """Return the offending fragment, or None when the payload looks safe."""
    low = payload.lower()
    for bad in FORBIDDEN_PAYLOAD_SUBSTRINGS:
        if bad in low:
            return bad
    return None


def sanitize_payloads(payloads: Iterable[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Split payloads into (allowed, [(payload, why_rejected)])."""
    good: list[str] = []
    bad: list[tuple[str, str]] = []
    for p in payloads:
        why = is_forbidden_payload(p)
        if why:
            bad.append((p, f"looks destructive ({why!r})"))
        else:
            good.append(p)
    return good, bad


# ---- the policy ------------------------------------------------------------

_SCHEME_RE = re.compile(r"^https?://", re.I)


@dataclass(slots=True)
class ScanPolicy:
    """The permission slip. ScanPolicy is the only thing that lets bytes fly."""

    #: Operator ticked the "I own this / I have permission" box.
    authorization_confirmed: bool = False
    #: Free-text record of *why* - ends up in the report header.
    authorization_note: str = ""
    #: Hostnames explicitly in scope. Empty means "whatever URL was passed",
    #: but only for hosts that survive the IP classification below.
    allowed_hosts: set[str] = field(default_factory=set)
    #: Enable active probing (payload injection). Passive checks always run.
    active_probing: bool = False
    #: Permit loopback/private targets. Only the bundled offline demo needs it.
    allow_private_network: bool = False
    #: Max requests per minute, applied per host.
    rate_per_minute: int = 20
    #: Hard ceiling on total requests so a crawler loop can't run away.
    max_requests: int = 400
    #: Refuse to send requests that could destroy data.
    allow_state_changing_methods: bool = False

    #: runtime state (not part of the permission slip)
    _limiter: RateLimiter = field(init=False, repr=False, default=None)  # type: ignore[assignment]
    _spent: int = field(init=False, repr=False, default=0)

    def __post_init__(self) -> None:
        self.allowed_hosts = {h.strip().lower() for h in self.allowed_hosts if h.strip()}
        self._limiter = RateLimiter(self.rate_per_minute)

    # -- gates -------------------------------------------------------------

    def require_authorization(self) -> None:
        if not self.authorization_confirmed:
            raise AuthorizationError(
                "authorization not confirmed. Set "
                "ScanPolicy(authorization_confirmed=True) only for systems you "
                "own or have written permission to test."
            )

    def check_url(self, url: str) -> str:
        """Validate one URL, return its normalized form, or raise."""
        self.require_authorization()

        if not _SCHEME_RE.match(url or ""):
            raise AuthorizationError(
                f"need a full http(s) URL, got {url!r}. no file://, no gopher://, "
                "no javascript: - this tool only speaks http."
            )

        host = host_of(url)
        if not host:
            raise AuthorizationError(f"no hostname in {url!r}")

        if self.allowed_hosts and host not in self.allowed_hosts:
            raise AuthorizationError(
                f"{host} is not in scope. allowed_hosts={sorted(self.allowed_hosts)}"
            )

        if not self.allow_private_network:
            ok, blocked = resolve_and_classify(host)
            if blocked:
                reasons = ", ".join(f"{ip} ({why})" for ip, why in blocked)
                raise AuthorizationError(
                    f"{host} resolves into network space we refuse to touch: "
                    f"{reasons}. If this is your own box set "
                    "allow_private_network=True."
                )
            if not ok:
                raise AuthorizationError(f"{host} has no usable public address")
        return url

    def check_method(self, method: str) -> None:
        if method.upper() in STATE_CHANGING_METHODS and not self.allow_state_changing_methods:
            raise ConsentRequired(
                f"{method.upper()} changes state. enable "
                "allow_state_changing_methods=True only where you own the endpoint."
            )

    def check_payload(self, payload: str) -> None:
        why = is_forbidden_payload(payload)
        if why:
            raise ConsentRequired(
                f"payload rejected, it looks destructive ({why!r}). this tool "
                "detects, it does not damage."
            )

    def throttle(self) -> None:
        if self._spent >= self.max_requests:
            raise AuthorizationError(
                f"request budget of {self.max_requests} spent. raise max_requests "
                "if you really mean it."
            )
        self._limiter.take()
        self._spent += 1

    # -- report helper -----------------------------------------------------

    @property
    def requests_sent(self) -> int:
        return self._spent

    @property
    def throttle_delay(self) -> float:
        return round(self._limiter.slept, 2)

    def header_block(self) -> str:
        mode = "active probing" if self.active_probing else "passive only"
        return (
            f"{BANNER}\n"
            f"Mode: {mode}\n"
            f"Authorized by: {self.authorization_note or 'unnamed operator'}\n"
            f"Rate limit: {self.rate_per_minute} req/min, budget {self.max_requests}"
        )
