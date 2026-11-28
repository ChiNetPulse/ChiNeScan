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


def test_native_linux_availability_accepts_complete_delegated_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "delegated"
    root.mkdir()
    (root / "cgroup.controllers").write_text("cpu memory pids", encoding="ascii")
    (root / "cgroup.subtree_control").write_text("+cpu +memory +pids", encoding="ascii")
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    monkeypatch.setattr(isolation.shutil, "which", lambda _: "/usr/bin/unshare")
    monkeypatch.setattr(isolation.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(isolation, "_landlock_supported", lambda: True)
    monkeypatch.setattr(isolation.os, "access", lambda *_: True)
    monkeypatch.setenv("CHINESCAN_CGROUP_ROOT", str(root))

    class FakePath:
        def __init__(self, value: str) -> None:
            self.value = value

        def resolve(self) -> FakePath:
            return self

        def __truediv__(self, other: str) -> FakePath:
            return FakePath(f"{self.value}/{other}")

        def is_file(self) -> bool:
            return self.value.endswith(("cgroup.controllers", "cgroup.subtree_control"))

        def read_text(self) -> str:
            return "cpu memory pids" if self.value.endswith("controllers") else "+cpu +memory +pids"

    monkeypatch.setattr(isolation, "Path", FakePath)
    request = LinuxIsolationRequest(
        namespaces=True,
        cgroup=True,
        seccomp=True,
        filesystem=True,
        filesystem_read_roots=("/usr",),
    )
    assert native_linux_available(request) == (True, None)


def test_linux_cgroup_join_self_and_join_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "delegated"
    root.mkdir()
    monkeypatch.setenv("CHINESCAN_CGROUP_ROOT", str(root))
    cgroup = LinuxCgroup(cpu_seconds=1, memory_bytes=1, max_processes=1)
    (cgroup.path / "cgroup.procs").write_text("", encoding="ascii")
    cgroup.join_self()
    assert (cgroup.path / "cgroup.procs").read_text() == str(isolation.os.getpid())

    monkeypatch.setattr(
        Path, "write_text", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("denied"))
    )
    with pytest.raises(LinuxIsolationUnavailable, match="could not join"):
        cgroup.join(22)


def test_namespace_command_without_boundary_returns_original_command() -> None:
    command = [sys.executable, "-c", "pass"]
    assert namespace_command(command, LinuxIsolationRequest()) == command


def test_apply_filesystem_boundary_installs_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    calls: list[tuple[int, ...]] = []
    monkeypatch.setattr(isolation, "_landlock_supported", lambda: True)
    monkeypatch.setattr(isolation, "apply_no_new_privs", lambda: calls.append((38,)))

    def fake_syscall(number: int, *arguments: int) -> int:
        calls.append((number,))
        return 10 if number == 444 else 0

    monkeypatch.setattr(isolation, "_syscall", fake_syscall)
    monkeypatch.setattr(isolation.os, "open", lambda *_args, **_kwargs: 42)
    monkeypatch.setattr(isolation.os, "close", lambda _fd: None)
    apply_filesystem_boundary((str(root),), (str(root),))
    assert calls[0] == (38,)
    assert (444,) in calls and (445,) in calls and (446,) in calls


def test_apply_no_new_privs_delegates_to_prctl(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[int, int]] = []
    monkeypatch.setattr(isolation, "_prctl", lambda option, arg: seen.append((option, arg)))
    isolation.apply_no_new_privs()
    assert seen == [(38, 1)]


def test_drop_capabilities_uses_capset(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, object]] = []

    class FakeCapset:
        argtypes: object = None
        restype: object = None

        def __call__(self, header: object, data: object) -> int:
            calls.append((header, data))
            return 0

    class FakeLibc:
        capset = FakeCapset()

    monkeypatch.setattr(isolation.ctypes, "CDLL", lambda *_args, **_kwargs: FakeLibc())
    isolation.drop_capabilities()
    assert len(calls) == 1


def test_apply_seccomp_installs_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    class FakeFunction:
        argtypes: object = None
        restype: object = None

        def __call__(self, *args: object) -> int:
            calls.append(args)
            return 0

    class FakeLibc:
        prctl = FakeFunction()

    monkeypatch.setattr(isolation.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(isolation.ctypes, "CDLL", lambda *_args, **_kwargs: FakeLibc())
    isolation.apply_seccomp()
    assert len(calls) == 2
    assert calls[0][0] == 38 and calls[1][0] == 22


def test_linux_worker_bootstrap_executes_after_controls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import chinescan.core.linux_worker_bootstrap as bootstrap

    marker = tmp_path / "cgroup.procs"
    marker.write_text("", encoding="ascii")
    seen: list[str] = []
    monkeypatch.setenv("CHINESCAN_CGROUP_PATH", str(tmp_path))
    monkeypatch.setenv("CHINESCAN_DROP_CAPABILITIES", "1")
    monkeypatch.setenv("CHINESCAN_SECCOMP", "1")
    monkeypatch.setenv("CHINESCAN_LANDLOCK", "1")
    monkeypatch.setenv("CHINESCAN_FS_READ_ROOTS", "/usr:/bin")
    monkeypatch.setenv("CHINESCAN_FS_WRITE_ROOTS", "/tmp")
    monkeypatch.setattr(bootstrap.os, "pathsep", ":")
    monkeypatch.setattr(bootstrap, "drop_capabilities", lambda: seen.append("caps"))
    monkeypatch.setattr(bootstrap, "apply_seccomp", lambda: seen.append("seccomp"))
    monkeypatch.setattr(
        bootstrap,
        "apply_filesystem_boundary",
        lambda reads, writes: seen.append(f"fs:{len(reads)}:{len(writes)}"),
    )
    monkeypatch.setattr(bootstrap.os, "getpid", lambda: 99)
    monkeypatch.setattr(bootstrap.os, "execvpe", lambda *args: seen.append("exec"))
    monkeypatch.setattr(bootstrap.sys, "argv", ["bootstrap", "--", "scanner", "--safe"])

    assert bootstrap.main() == 125
    assert marker.read_text() == "99"
    assert seen == ["caps", "seccomp", "fs:2:1", "exec"]


def test_linux_worker_bootstrap_rejects_invalid_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import chinescan.core.linux_worker_bootstrap as bootstrap

    monkeypatch.setattr(bootstrap.sys, "argv", ["bootstrap"])
    assert bootstrap.main() == 125

    monkeypatch.setattr(bootstrap.sys, "argv", ["bootstrap", "--", "scanner"])
    monkeypatch.setattr(
        bootstrap, "drop_capabilities", lambda: (_ for _ in ()).throw(OSError("denied"))
    )
    monkeypatch.setenv("CHINESCAN_DROP_CAPABILITIES", "1")
    assert bootstrap.main() == 125


def test_native_linux_availability_rejects_unsupported_seccomp_architecture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    monkeypatch.setattr(isolation.platform, "machine", lambda: "aarch64")
    assert native_linux_available(LinuxIsolationRequest(seccomp=True)) == (
        False,
        "seccomp_architecture_not_supported",
    )


def test_native_linux_availability_rejects_unsafe_cgroup_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    monkeypatch.setenv("CHINESCAN_CGROUP_ROOT", "/sys/fs/cgroup")

    class FakePath:
        def __init__(self, value: str) -> None:
            self.value = value

        def resolve(self) -> FakePath:
            return self

        def __eq__(self, other: object) -> bool:
            return isinstance(other, FakePath) and self.value == other.value

    monkeypatch.setattr(isolation, "Path", FakePath)
    assert native_linux_available(LinuxIsolationRequest(cgroup=True)) == (
        False,
        "cgroup_root_not_allowed",
    )


def test_native_linux_availability_rejects_missing_cgroup_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "name", "posix")
    root = tmp_path / "delegated"
    root.mkdir()
    monkeypatch.setenv("CHINESCAN_CGROUP_ROOT", str(root))

    class FakePath:
        def __init__(self, value: str) -> None:
            self.value = value

        def resolve(self) -> FakePath:
            return self

        def __truediv__(self, other: str) -> FakePath:
            return FakePath(f"{self.value}/{other}")

        def is_file(self) -> bool:
            return False

    monkeypatch.setattr(isolation, "Path", FakePath)
    assert native_linux_available(LinuxIsolationRequest(cgroup=True)) == (
        False,
        "cgroup_v2_unavailable",
    )


def test_namespace_command_rejects_missing_runtime_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation.shutil, "which", lambda _: None)
    with pytest.raises(LinuxIsolationUnavailable, match="unshare"):
        namespace_command(["scanner"], LinuxIsolationRequest(namespaces=True))

    monkeypatch.setattr(isolation.shutil, "which", lambda _: "/usr/bin/unshare")
    monkeypatch.setattr("chinescan.core.network_policy.deployment_helper", lambda: None)
    with pytest.raises(LinuxIsolationUnavailable, match="network policy"):
        namespace_command(
            ["scanner"],
            LinuxIsolationRequest(
                namespaces=True,
                network=True,
                network_mode="approved_destinations",
                network_policy_json="{}",
            ),
        )


def test_filesystem_boundary_rejects_kernel_setup_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    monkeypatch.setattr(isolation, "apply_no_new_privs", lambda: None)
    monkeypatch.setattr(isolation, "_landlock_supported", lambda: False)
    with pytest.raises(LinuxIsolationUnavailable, match="unavailable"):
        apply_filesystem_boundary((str(root),), ())

    monkeypatch.setattr(isolation, "_landlock_supported", lambda: True)
    monkeypatch.setattr(isolation, "_syscall", lambda number, *args: -1 if number == 444 else 0)
    with pytest.raises(LinuxIsolationUnavailable, match="ruleset creation"):
        apply_filesystem_boundary((str(root),), ())


@pytest.mark.parametrize(
    "failure_number, message", [(445, "filesystem rule"), (446, "restriction")]
)
def test_filesystem_boundary_rejects_rule_and_restriction_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_number: int,
    message: str,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    monkeypatch.setattr(isolation, "apply_no_new_privs", lambda: None)
    monkeypatch.setattr(isolation, "_landlock_supported", lambda: True)
    monkeypatch.setattr(
        isolation,
        "_syscall",
        lambda number, *args: 10 if number == 444 else -1 if number == failure_number else 0,
    )
    monkeypatch.setattr(isolation.os, "open", lambda *_args, **_kwargs: 42)
    monkeypatch.setattr(isolation.os, "close", lambda _fd: None)
    with pytest.raises(LinuxIsolationUnavailable, match=message):
        apply_filesystem_boundary((str(root),), ())


def test_privilege_reduction_failures_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingCapset:
        argtypes: object = None
        restype: object = None

        def __call__(self, *_args: object) -> int:
            return -1

    class FailingLibc:
        capset = FailingCapset()

    monkeypatch.setattr(isolation.ctypes, "CDLL", lambda *_args, **_kwargs: FailingLibc())
    with pytest.raises(LinuxIsolationUnavailable, match="capability reduction"):
        isolation.drop_capabilities()

    class FailingPrctl:
        argtypes: object = None
        restype: object = None

        def __call__(self, *_args: object) -> int:
            return -1

    class SeccompLibc:
        prctl = FailingPrctl()

    monkeypatch.setattr(isolation.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(isolation.ctypes, "CDLL", lambda *_args, **_kwargs: SeccompLibc())
    monkeypatch.setattr(isolation, "apply_no_new_privs", lambda: None)
    monkeypatch.setattr(isolation.ctypes, "get_errno", lambda: 1)
    with pytest.raises(LinuxIsolationUnavailable, match="seccomp initialization"):
        isolation.apply_seccomp()
