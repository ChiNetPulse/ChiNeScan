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
    platform_supported: bool
    runtime_available: bool
    hardened_supported: bool
    process_tree_cleanup: bool
    cpu_memory_limits: bool
    network_isolation: bool
    enforced_controls: tuple[str, ...]
    unavailable_controls: tuple[str, ...]
    reasons: tuple[str, ...]


def _probe_posix_rlimits() -> bool:
    """Verify POSIX rlimit constants and runtime getrlimit queries succeed."""
    try:
        import resource  # noqa: PLC0415

        getrlimit = getattr(resource, "getrlimit", None)
        if not callable(getrlimit):
            return False
        required = ("RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_NPROC", "RLIMIT_NOFILE", "RLIMIT_FSIZE")
        for name in required:
            limit_id = getattr(resource, name, None)
            if limit_id is None:
                return False
            getrlimit(limit_id)
        return True
    except (ImportError, OSError, ValueError, AttributeError):
        return False


def detect_isolation_capabilities() -> IsolationCapabilities:
    """Detect enforceable primitives without mutating host state."""
    platform = sys.platform
    platform_supported = os.name == "posix" and platform.startswith("linux")
    reasons: list[str] = []
    if not platform_supported:
        reasons.append("hardened_linux_worker_required")
    runtime_available = _probe_posix_rlimits() if platform_supported else False
    if platform_supported and not runtime_available:
        reasons.append("posix_resource_limits_unavailable")
    hardened_supported = platform_supported and runtime_available
    process_tree_cleanup = os.name in {"posix", "nt"}
    enforced_controls: list[str] = []
    unavailable_controls: list[str] = []
    if process_tree_cleanup:
        enforced_controls.append("process_tree_cleanup")
    else:
        unavailable_controls.append("process_tree_cleanup")
    if hardened_supported:
        enforced_controls.append("posix_rlimits")
    else:
        unavailable_controls.append("posix_rlimits")
    # Network namespaces require deployment privileges and are deliberately not
    # inferred from a local process.  Operators must provision egress controls.
    unavailable_controls.append("network_isolation")
    reasons.append("network_namespace_not_application_managed")
    return IsolationCapabilities(
        platform=platform,
        platform_supported=platform_supported,
        runtime_available=runtime_available,
        hardened_supported=hardened_supported,
        process_tree_cleanup=process_tree_cleanup,
        cpu_memory_limits=hardened_supported,
        network_isolation=False,
        enforced_controls=tuple(enforced_controls),
        unavailable_controls=tuple(unavailable_controls),
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
    if os.name != "posix" or not _probe_posix_rlimits():
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
        "platform_supported": capabilities.platform_supported,
        "runtime_available": capabilities.runtime_available,
        "hardened_supported": capabilities.hardened_supported,
        "process_tree_cleanup": capabilities.process_tree_cleanup,
        "cpu_memory_limits": capabilities.cpu_memory_limits,
        "network_isolation": capabilities.network_isolation,
        "enforced_controls": list(capabilities.enforced_controls),
        "unavailable_controls": list(capabilities.unavailable_controls),
        "reasons": list(capabilities.reasons),
    }
