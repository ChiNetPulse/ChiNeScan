from __future__ import annotations

import sys
from pathlib import Path

import pytest

import chinescan.core.linux_isolation as isolation
from chinescan.core.linux_isolation import (
    LinuxCgroup,
    LinuxIsolationRequest,
    LinuxIsolationUnavailable,
    apply_filesystem_boundary,
    namespace_command,
    native_linux_available,
)


def test_native_linux_availability_rejects_missing_namespace_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    monkeypatch.setattr(isolation.shutil, "which", lambda _: None)
    available, reason = native_linux_available(LinuxIsolationRequest(namespaces=True))
    assert not available and reason == "unshare_binary_unavailable"


def test_native_linux_availability_rejects_approved_network_without_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    monkeypatch.setattr(isolation.shutil, "which", lambda _: "/usr/bin/unshare")
    request = LinuxIsolationRequest(
        network=True, network_mode="approved_destinations", network_policy_json=None
    )
    available, reason = native_linux_available(request)
    assert not available and reason == "network_policy_required"


def test_native_linux_availability_rejects_missing_network_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    monkeypatch.setattr(isolation.shutil, "which", lambda _: "/usr/bin/unshare")
    monkeypatch.setattr("chinescan.core.network_policy.deployment_helper", lambda: None)
    request = LinuxIsolationRequest(
        network=True, network_mode="approved_destinations", network_policy_json="{}"
    )
    available, reason = native_linux_available(request)
    assert not available and reason == "network_policy_helper_unavailable"


def test_native_linux_availability_checks_filesystem_and_landlock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    unavailable, reason = native_linux_available(LinuxIsolationRequest(filesystem=True))
    assert not unavailable and reason == "filesystem_read_roots_required"

    monkeypatch.setattr(isolation, "_landlock_supported", lambda: False)
    unavailable, reason = native_linux_available(
        LinuxIsolationRequest(filesystem=True, filesystem_read_roots=("/usr",))
    )
    assert not unavailable and reason == "landlock_unavailable"


def test_native_linux_availability_checks_delegated_cgroup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    root = tmp_path / "delegated"
    root.mkdir()
    (root / "cgroup.controllers").write_text("cpu memory pids", encoding="ascii")
    (root / "cgroup.subtree_control").write_text("+cpu +memory +pids", encoding="ascii")

    available_without_env, reason = native_linux_available(LinuxIsolationRequest(cgroup=True))
    assert not available_without_env and reason == "cgroup_delegated_root_required"


def test_cgroup_lifecycle_is_execution_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "delegated"
    root.mkdir()
    monkeypatch.setenv("CHINESCAN_CGROUP_ROOT", str(root))
    cgroup = LinuxCgroup(cpu_seconds=2, memory_bytes=4096, max_processes=3)

    assert cgroup.path.parent == root / "chinescan"
    assert (cgroup.path / "cpu.max").read_text() == "20000 100000"
    assert (cgroup.path / "memory.max").read_text() == "4096"
    assert (cgroup.path / "pids.max").read_text() == "3"
    cgroup.join(1234)
    assert (cgroup.path / "cgroup.procs").read_text() == "1234"
    for child in cgroup.path.iterdir():
        child.unlink()
    cgroup.cleanup()
    assert not cgroup.path.exists()


def test_cgroup_initialization_fails_closed_for_unwritable_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "delegated"
    root.mkdir()
    monkeypatch.setenv("CHINESCAN_CGROUP_ROOT", str(root / "missing"))
    monkeypatch.setattr(
        Path, "mkdir", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("denied"))
    )

    with pytest.raises(LinuxIsolationUnavailable, match="cgroup initialization failed"):
        LinuxCgroup(cpu_seconds=1, memory_bytes=1, max_processes=1)


def test_approved_network_namespace_uses_deployment_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    monkeypatch.setattr(isolation.shutil, "which", lambda _: "/usr/bin/unshare")
    monkeypatch.setattr(
        "chinescan.core.network_policy.deployment_helper", lambda: "/usr/local/bin/helper"
    )
    command = namespace_command(
        [sys.executable, "-c", "pass"],
        LinuxIsolationRequest(
            namespaces=True,
            network=True,
            network_mode="approved_destinations",
            network_policy_json="/tmp/policy.json",
        ),
    )
    assert command[:4] == ["/usr/local/bin/helper", "--policy-json", "/tmp/policy.json", "--"]
    assert "/usr/bin/unshare" in command


def test_filesystem_boundary_fails_closed_without_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation, "_landlock_supported", lambda: True)
    with pytest.raises(LinuxIsolationUnavailable, match="read roots"):
        apply_filesystem_boundary((), ())
