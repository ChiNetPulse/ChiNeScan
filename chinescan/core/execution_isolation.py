"""Fail-closed execution isolation and resource-limit primitives.

The application can supervise a child process on every supported host, but a
hardened scanner worker is only advertised when the host can enforce POSIX
resource limits.  Windows development hosts are intentionally reported as
unsupported for the hardened profile; the existing Job Object cleanup remains
useful supervision, but is not represented as equivalent isolation.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any


class IsolationUnavailableError(RuntimeError):
    """Raised when a requested execution profile cannot be enforced safely."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class IsolationProfile:
    """Administrative worker profile; callers cannot override these values."""

    name: str = "restricted-scanner"
    cpu_seconds: int = 60
    memory_bytes: int = 512 * 1024 * 1024
    max_processes: int = 64
    max_open_files: int = 256
    max_file_bytes: int = 33_554_432
    network_isolation_required: bool = False


@dataclass(frozen=True)
class IsolationCapabilities:
    """Host capability report safe to expose to an operator."""

    platform: str
    hardened_supported: bool
    process_tree_cleanup: bool
    cpu_memory_limits: bool
    network_isolation: bool
    reasons: tuple[str, ...]


def detect_isolation_capabilities() -> IsolationCapabilities:
    """Detect enforceable primitives without probing or changing the host."""
    platform = sys.platform
    linux = os.name == "posix" and platform.startswith("linux")
    reasons: list[str] = []
    if not linux:
        reasons.append("hardened_linux_worker_required")
    try:
        import resource  # noqa: PLC0415

        limits = all(
            hasattr(resource, name)
            for name in ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_NPROC", "RLIMIT_NOFILE", "RLIMIT_FSIZE")
        )
    except ImportError:
        limits = False
    if linux and not limits:
        reasons.append("posix_resource_limits_unavailable")
    # Network namespaces require deployment privileges and are deliberately not
    # inferred from a local process.  Operators must provision egress controls.
    reasons.append("network_namespace_not_application_managed")
    return IsolationCapabilities(
        platform=platform,
        hardened_supported=linux and limits,
        process_tree_cleanup=True,
        cpu_memory_limits=linux and limits,
        network_isolation=False,
        reasons=tuple(reasons),
    )


def require_isolation(profile: IsolationProfile) -> IsolationCapabilities:
    """Validate that the requested profile can be enforced before launch."""
    capabilities = detect_isolation_capabilities()
    if not capabilities.hardened_supported:
        raise IsolationUnavailableError(
            "ISOLATION_UNAVAILABLE", "The hardened scanner worker is unavailable on this host."
        )
    if profile.network_isolation_required and not capabilities.network_isolation:
        raise IsolationUnavailableError(
            "NETWORK_ISOLATION_UNAVAILABLE",
            "The configured scanner profile requires deployment-managed network isolation.",
        )
    return capabilities


def make_preexec_fn(profile: IsolationProfile) -> Any:
    """Return a POSIX-only pre-exec hook that applies hard process limits."""
    if os.name != "posix":
        raise IsolationUnavailableError(
            "ISOLATION_UNAVAILABLE", "POSIX resource limits are required for this profile."
        )
    import resource  # noqa: PLC0415

    resource_module: Any = resource

    def apply_limits() -> None:
        resource_module.setrlimit(
            resource_module.RLIMIT_CPU,
            (profile.cpu_seconds, profile.cpu_seconds),
        )
        resource_module.setrlimit(
            resource_module.RLIMIT_AS,
            (profile.memory_bytes, profile.memory_bytes),
        )
        resource_module.setrlimit(
            resource_module.RLIMIT_NPROC,
            (profile.max_processes, profile.max_processes),
        )
        resource_module.setrlimit(
            resource_module.RLIMIT_NOFILE,
            (profile.max_open_files, profile.max_open_files),
        )
        resource_module.setrlimit(
            resource_module.RLIMIT_FSIZE,
            (profile.max_file_bytes, profile.max_file_bytes),
        )

    return apply_limits


def isolation_status() -> dict[str, object]:
    """Return non-sensitive readiness data for authenticated diagnostics."""
    capabilities = detect_isolation_capabilities()
    return {
        "platform": capabilities.platform,
        "hardened_supported": capabilities.hardened_supported,
        "process_tree_cleanup": capabilities.process_tree_cleanup,
        "cpu_memory_limits": capabilities.cpu_memory_limits,
        "network_isolation": capabilities.network_isolation,
        "reasons": list(capabilities.reasons),
    }
