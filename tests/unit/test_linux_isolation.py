from __future__ import annotations

import sys

import pytest

from chinescan.core.execution_isolation import IsolationProfile
from chinescan.core.linux_isolation import (
    LinuxIsolationRequest,
    namespace_command,
    native_linux_available,
)
from chinescan.core.subprocess_supervision import (
    SubprocessExecutionError,
    run_supervised_subprocess,
)


def test_filesystem_profile_is_unavailable_until_boundary_is_initialized() -> None:
    available, reason = native_linux_available(LinuxIsolationRequest(filesystem=True))

    assert not available
    assert reason in {"linux_host_required", "filesystem_read_roots_required"}


def test_namespace_command_uses_combined_namespace_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("chinescan.core.linux_isolation.shutil.which", lambda _: "/usr/bin/unshare")

    command = namespace_command(
        [sys.executable, "-c", "pass"],
        LinuxIsolationRequest(namespaces=True, network=True),
    )

    assert command[0] == "/usr/bin/unshare"
    assert "--user" in command
    assert "--map-current-user" in command
    assert "--mount" in command
    assert "--pid" in command
    assert "--net" in command
    assert "chinescan.core.linux_worker_bootstrap" in command


def test_filesystem_profile_uses_bootstrap_before_exec() -> None:
    command = namespace_command(
        [sys.executable, "-c", "pass"],
        LinuxIsolationRequest(filesystem=True, filesystem_read_roots=("/usr",)),
    )

    assert command[:3] == [sys.executable, "-m", "chinescan.core.linux_worker_bootstrap"]


def test_cgroup_requires_explicit_delegated_subtree(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHINESCAN_CGROUP_ROOT", raising=False)

    available, reason = native_linux_available(LinuxIsolationRequest(cgroup=True))

    assert not available
    assert reason in {"linux_host_required", "cgroup_delegated_root_required"}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only launcher test")
def test_required_linux_boundary_failure_rejects_before_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "chinescan.core.subprocess_supervision.native_linux_available",
        lambda request: (False, "test_boundary_unavailable"),
    )
    profile = IsolationProfile(linux_namespaces_required=True)

    with pytest.raises(SubprocessExecutionError, match="test_boundary_unavailable") as exc:
        run_supervised_subprocess(
            [sys.executable, "-c", "raise SystemExit(99)"],
            isolation_profile=profile,
        )

    assert exc.value.code == "SUBPROCESS_ISOLATION_UNAVAILABLE"
