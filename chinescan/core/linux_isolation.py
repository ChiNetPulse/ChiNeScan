"""Linux worker bootstrap and execution-scoped cgroup integration.

The launcher is deliberately conservative. It only advertises the native
profile when the kernel-facing helpers, namespace launcher, and delegated
cgroup controllers are available. Network isolation is deny-all in the native
namespace profile; an approved egress allowlist requires deployment firewall
provisioning and is not synthesized by this module.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4


class LinuxIsolationUnavailable(RuntimeError):
    """A mandatory Linux worker boundary could not be established."""


@dataclass(frozen=True)
class LinuxIsolationRequest:
    namespaces: bool = False
    cgroup: bool = False
    seccomp: bool = False
    filesystem: bool = False
    network: bool = False
    filesystem_read_roots: tuple[str, ...] = ()
    filesystem_write_roots: tuple[str, ...] = ()
    network_mode: str = "deny_all"
    network_policy_json: str | None = None


def native_linux_available(request: LinuxIsolationRequest) -> tuple[bool, str | None]:
    if not sys.platform.startswith("linux") or os.name != "posix":
        return False, "linux_host_required"
    if request.namespaces and shutil.which("unshare") is None:
        return False, "unshare_binary_unavailable"
    if request.network and request.network_mode == "approved_destinations":
        if not request.network_policy_json:
            return False, "network_policy_required"
        from chinescan.core.network_policy import deployment_helper

        if deployment_helper() is None:
            return False, "network_policy_helper_unavailable"
    if request.seccomp and platform.machine().lower() not in {"x86_64", "amd64"}:
        return False, "seccomp_architecture_not_supported"
    if request.filesystem and not request.filesystem_read_roots:
        return False, "filesystem_read_roots_required"
    if request.filesystem and not _landlock_supported():
        return False, "landlock_unavailable"
    if request.cgroup:
        configured_root = os.environ.get("CHINESCAN_CGROUP_ROOT")
        if not configured_root:
            return False, "cgroup_delegated_root_required"
        root = Path(configured_root).resolve()
        if root == Path("/sys/fs/cgroup"):
            return False, "cgroup_root_not_allowed"
        if not (root / "cgroup.controllers").is_file():
            return False, "cgroup_v2_unavailable"
        controllers = set((root / "cgroup.controllers").read_text().split())
        if not {"cpu", "memory", "pids"}.issubset(controllers):
            return False, "required_cgroup_controllers_unavailable"
        subtree_control = set((root / "cgroup.subtree_control").read_text().split())
        if not {"+cpu", "+memory", "+pids"}.issubset(subtree_control):
            return False, "required_cgroup_controllers_not_delegated"
        if not os.access(root, os.W_OK):
            return False, "cgroup_delegation_unavailable"
    return True, None


def _syscall(number: int, *arguments: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    return int(syscall(number, *arguments))


def _landlock_supported() -> bool:
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        return False
    # landlock_create_ruleset(0, NULL, 0) returns the supported ABI version.
    result = _syscall(444, 0, 0, 0)
    return result >= 1


def apply_filesystem_boundary(read_roots: tuple[str, ...], write_roots: tuple[str, ...]) -> None:
    """Restrict filesystem access to explicit roots with Linux Landlock."""
    if not read_roots:
        raise LinuxIsolationUnavailable("filesystem read roots are required")
    if not _landlock_supported():
        raise LinuxIsolationUnavailable("Landlock is unavailable")
    # Landlock restriction requires either CAP_SYS_ADMIN or no_new_privs.
    apply_no_new_privs()

    # Landlock ABI v1 rights.  The default action for handled rights is deny.
    handled_rights = 0x3F

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]

    class PathBeneath(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]

    attr = RulesetAttr(handled_rights, 0)
    ruleset = _syscall(444, ctypes.addressof(attr), ctypes.sizeof(attr), 1)
    if ruleset < 0:
        raise LinuxIsolationUnavailable("Landlock ruleset creation failed")
    try:
        read_access = 0x01 | 0x04 | 0x08
        write_access = handled_rights
        roots = tuple(dict.fromkeys((*read_roots, *write_roots)))
        resolved_write_roots = {str(Path(item).resolve()) for item in write_roots}
        for root in roots:
            path = Path(root).resolve()
            fd = os.open(
                path,
                getattr(os, "O_PATH", 0o10000000) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                allowed = write_access if str(path) in resolved_write_roots else read_access
                rule = PathBeneath(allowed, fd)
                if _syscall(445, ruleset, 1, ctypes.addressof(rule), 0) < 0:
                    raise LinuxIsolationUnavailable("Landlock filesystem rule failed")
            finally:
                os.close(fd)
        if _syscall(446, ruleset, 0) < 0:
            raise LinuxIsolationUnavailable("Landlock restriction failed")
    finally:
        os.close(ruleset)


class LinuxCgroup:
    """Own one delegated cgroup and remove only that cgroup on cleanup."""

    def __init__(self, *, cpu_seconds: int, memory_bytes: int, max_processes: int) -> None:
        root = Path(os.environ.get("CHINESCAN_CGROUP_ROOT", "/sys/fs/cgroup"))
        self.path = root / "chinescan" / f"execution-{uuid4().hex}"
        try:
            self.path.parent.mkdir(mode=0o700, exist_ok=True)
            self.path.mkdir(mode=0o700)
            (self.path / "cpu.max").write_text(f"{max(1, cpu_seconds * 10000)} 100000")
            (self.path / "memory.max").write_text(str(max(1, memory_bytes)))
            (self.path / "pids.max").write_text(str(max(1, max_processes)))
        except (OSError, ValueError) as exc:
            self.cleanup()
            raise LinuxIsolationUnavailable("cgroup initialization failed") from exc

    def join_self(self) -> None:
        try:
            (self.path / "cgroup.procs").write_text(str(os.getpid()))
        except OSError as exc:
            raise LinuxIsolationUnavailable("worker could not join its cgroup") from exc

    def join(self, pid: int) -> None:
        try:
            (self.path / "cgroup.procs").write_text(str(pid))
        except OSError as exc:
            raise LinuxIsolationUnavailable("worker process could not join its cgroup") from exc

    def cleanup(self) -> None:
        try:
            if self.path.exists():
                self.path.rmdir()
        except OSError:
            pass


def namespace_command(command: list[str], request: LinuxIsolationRequest) -> list[str]:
    bootstrap = [sys.executable, "-m", "chinescan.core.linux_worker_bootstrap", "--", *command]
    if not request.namespaces:
        return bootstrap if request.cgroup or request.seccomp or request.filesystem else command
    unshare = shutil.which("unshare")
    if unshare is None:
        raise LinuxIsolationUnavailable("unshare binary unavailable")
    flags = [
        "--user",
        "--map-current-user",
        "--mount",
        "--pid",
        "--fork",
        "--mount-proc",
        "--uts",
        "--ipc",
    ]
    if request.network and request.network_mode == "deny_all":
        flags.append("--net")
    wrapped = [unshare, *flags, "--", *bootstrap]
    if request.network and request.network_mode == "approved_destinations":
        from chinescan.core.network_policy import deployment_helper

        helper = deployment_helper()
        if helper is None or request.network_policy_json is None:
            raise LinuxIsolationUnavailable("network policy helper unavailable")
        return [helper, "--policy-json", request.network_policy_json, "--", *wrapped]
    return wrapped


def _prctl(option: int, arg: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.prctl
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    function.restype = ctypes.c_int
    if function(option, arg, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise LinuxIsolationUnavailable(os.strerror(error))


def apply_no_new_privs() -> None:
    _prctl(38, 1)  # PR_SET_NO_NEW_PRIVS


def drop_capabilities() -> None:
    # Clearing the effective, permitted, and inheritable sets is safe for an
    # unprivileged user-namespace worker.  Dropping the bounding set requires
    # CAP_SETPCAP and is intentionally not requested from the scanner profile;
    # callers must not treat the bounding set as independently verified.
    libc = ctypes.CDLL(None, use_errno=True)
    capset = libc.capset
    capset.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    capset.restype = ctypes.c_int

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header = Header(0x20080522, 0)
    data = (Data * 2)()
    if capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise LinuxIsolationUnavailable("capability reduction failed")


def apply_seccomp() -> None:
    """Install a small deny-list filter before the scanner execs."""
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise LinuxIsolationUnavailable("seccomp architecture is unsupported")
    libc = ctypes.CDLL(None, use_errno=True)
    apply_no_new_privs()

    class Filter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]

    denied = {
        16,  # ioctl
        157,  # prctl
        165,  # mount
        166,  # umount2
        155,  # pivot_root
        308,  # setns
        272,  # unshare
        101,  # ptrace
        321,  # bpf
        298,  # perf_event_open
        250,  # keyctl
        246,  # kexec_load
        167,  # swapon
        168,  # swapoff
        256,  # open_by_handle_at
    }
    instructions = [
        Filter(0x20, 0, 0, 4),
        Filter(0x15, 1, 0, 0xC000003E),
        Filter(0x06, 0, 0, 0x80000000),
        Filter(0x20, 0, 0, 0),
    ]
    for syscall in sorted(denied):
        instructions.extend(
            (Filter(0x15, 0, 1, syscall), Filter(0x06, 0, 0, 0x00050000 | errno.EPERM))
        )
    instructions.append(Filter(0x06, 0, 0, 0x7FFF0000))
    array = (Filter * len(instructions))(*instructions)
    program = Program(len(instructions), array)
    function = libc.prctl
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    function.restype = ctypes.c_int
    if function(22, 2, ctypes.addressof(program), 0, 0) != 0:  # PR_SET_SECCOMP, SECCOMP_MODE_FILTER
        error = ctypes.get_errno()
        raise LinuxIsolationUnavailable(f"seccomp initialization failed: {os.strerror(error)}")
