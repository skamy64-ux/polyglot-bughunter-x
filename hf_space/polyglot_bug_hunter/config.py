"""Runtime knobs. Boring on purpose - everything a scanner needs, nothing else."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# A normal, honest browser UA. Spoofing a scanner to look like Chrome buys us
# nothing and makes us indistinguishable from the actual bad guys.
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "PolyglotBugHunter-X/1.0 (+authorized-security-testing)"
)

# Markers we inject so a finding can be proven from the target's own response.
MARKER = "PBHX7"


@dataclass(slots=True)
class ScanConfig:
    """Everything the scanners read. Pass one of these to Hunter()."""

    # -- scope
    max_pages: int = 15
    max_depth: int = 2
    same_origin_only: bool = True

    # -- http
    timeout: float = 10.0
    user_agent: str = DEFAULT_UA
    verify_tls: bool = True
    follow_redirects: bool = True
    max_redirects: int = 3
    extra_headers: dict[str, str] = field(default_factory=dict)

    # -- probing
    payload_budget: int = 6        # payloads per parameter, keeps it polite
    form_budget: int = 4            # forms per page
    input_budget: int = 4           # text inputs per form

    # -- extras
    screenshot: bool = True
    screenshot_full_page: bool = True
    check_race: bool = False        # concurrency probes: noisy, off by default
    race_threads: int = 6
    timeout_delta_ms: int = 350     # margin used by timing-based heuristics

    # -- output
    output_dir: str = "artifacts"
    keep_screenshots: bool = True

    @classmethod
    def from_env(cls, **overrides: object) -> ScanConfig:
        """Env is for the Space, where env vars beat editing code."""
        cfg = cls()
        if v := os.getenv("PBHX_TIMEOUT"):
            cfg.timeout = float(v)
        if v := os.getenv("PBHX_MAX_PAGES"):
            cfg.max_pages = int(v)
        if v := os.getenv("PBHX_RPM"):
            cfg.rate_per_minute_override = int(v)  # type: ignore[attr-defined]
        if v := os.getenv("PBHX_VERIFY_TLS", "").lower() in ("0", "false", "no"):
            cfg.verify_tls = False
        for k, v in overrides.items():
            if v is not None and hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


@dataclass(slots=True)
class ModalityConfig:
    """Per-modality toggles so the Space can run just the cheap one on CPU."""

    text: bool = True
    image: bool = False
    audio: bool = False
    passive: bool = True

    def enabled(self) -> list[str]:
        return [n for n in ("text", "image", "audio", "passive") if getattr(self, n)]

    @classmethod
    def parse(cls, modes: list[str] | str | None) -> ModalityConfig:
        if not modes:
            return cls()
        if isinstance(modes, str):
            modes = [m.strip() for m in modes.split(",")]
        wanted = {m.strip().lower() for m in modes if m.strip()}
        return cls(
            text="text" in wanted,
            image="image" in wanted,
            audio="audio" in wanted,
            passive="passive" in wanted or not wanted,
        )
