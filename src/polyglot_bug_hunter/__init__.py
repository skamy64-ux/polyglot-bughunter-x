"""PolyglotBugHunter-X — a multimodal agent that watches, listens and reads
websites while it hunts bugs.

Quick start:

    from polyglot_bug_hunter import Hunter, ScanPolicy

    report = Hunter.demo()                       # offline demo, no setup
    print(report.risk_score)

    policy = ScanPolicy(authorization_confirmed=True,
                        authorization_note="my own staging box")
    report = Hunter(policy, modes=["text", "image"]).scan("https://staging.example")

Authorized use only. See `safety.LEGAL_NOTICE`.
"""

from __future__ import annotations

from .config import ModalityConfig, ScanConfig
from .hunter import (
    Hunter,
    available_capabilities,
    known_targets,
    version,
)
from .i18n import SUPPORTED, Translator, detect
from .models import (
    Asset,
    Confidence,
    Cvss,
    Evidence,
    Finding,
    Modality,
    ScanReport,
    Severity,
    cvss_to_severity,
)
from .safety import AuthorizationError, ScanPolicy, is_forbidden_payload

__version__ = version()
__all__ = [
    "SUPPORTED",
    "Asset",
    "AuthorizationError",
    "Confidence",
    "Cvss",
    "Evidence",
    "Finding",
    "Hunter",
    "Modality",
    "ModalityConfig",
    "ScanConfig",
    "ScanPolicy",
    "ScanReport",
    "Severity",
    "Translator",
    "__version__",
    "available_capabilities",
    "cvss_to_severity",
    "detect",
    "is_forbidden_payload",
    "known_targets",
    "version",
]
