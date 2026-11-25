"""Supervised subprocess execution with bounded output, deadlines, and tree cleanup."""

from __future__ import annotations

import ctypes
import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from chinescan.core.resource_governance import ExecutionDeadlineExceeded

DEFAULT_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "HOME",
        "USERPROFILE",
        "LOCALAPPDATA",
    }
)


class SubprocessExecutionError(RuntimeError):
    """Sanitized failure from a supervised subprocess invocation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SupervisedProcessResult:
    """Bounded result from a supervised child process."""

    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    terminated_reason: str | None = None


class _ProcessTreeJob:
    """Best-effort Windows Job Object wrapper for complete child process-tree termination."""

    def __init__(self) -> None:
        self._handle: int | None = None
        if os.name != "nt":
            return
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return
        try:
            # JOBOBJECT_EXTENDED_LIMIT_INFORMATION (InformationClass = 9)
            # Set JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000) so closing or terminating
            # the Job Object kills the entire child process tree.
            class _IoCounters(ctypes.Structure):
                _fields_ = [("ReadOperationCount", ctypes.c_uint64)] * 6

            class _BasicLimitInfo(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", ctypes.c_uint32),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", ctypes.c_uint32),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", ctypes.c_uint32),
                    ("SchedulingClass", ctypes.c_uint32),
                ]

            class _ExtendedLimitInfo(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _BasicLimitInfo),
                    ("IoInfo", _IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = _ExtendedLimitInfo()
            info.BasicLimitInformation.LimitFlags = 0x00002000
            ok = kernel32.SetInformationJobObject(
                handle, 9, ctypes.byref(info), ctypes.sizeof(info)
            )
            if ok:
                self._handle = int(handle)
                return
        except OSError:
            pass
        kernel32.CloseHandle(handle)

    def assign(self, process: subprocess.Popen[bytes]) -> bool:
        if os.name != "nt" or self._handle is None:
            return False
        proc_handle = getattr(process, "_handle", None)
        if proc_handle is None:
            return False
        kernel32 = ctypes.windll.kernel32
        return bool(kernel32.AssignProcessToJobObject(self._handle, int(proc_handle)))

    def terminate(self) -> bool:
        if os.name != "nt" or self._handle is None:
            return False
        kernel32 = ctypes.windll.kernel32
        return bool(kernel32.TerminateJobObject(self._handle, 1))

    def close(self) -> None:
        if os.name == "nt" and self._handle is not None:
            ctypes.windll.kernel32.CloseHandle(self._handle)
            self._handle = None


def resolve_executable(executable: str) -> str:
    """Resolve and validate an explicit executable path without shell expansion."""
    if not executable or any(ch in executable for ch in ("\x00", "\n", "\r")):
        raise SubprocessExecutionError("SUBPROCESS_INVALID_EXECUTABLE", "Invalid executable.")
    candidate = Path(executable)
    if candidate.is_absolute() or candidate.parent != Path("."):
        if not candidate.is_file():
            raise SubprocessExecutionError(
                "SUBPROCESS_EXECUTABLE_NOT_FOUND",
                "Configured executable is unavailable.",
            )
        return str(candidate.resolve())
    resolved = shutil.which(executable)
    if resolved is None:
        raise SubprocessExecutionError(
            "SUBPROCESS_EXECUTABLE_NOT_FOUND",
            "Required executable is not installed or not available on PATH.",
        )
    return resolved


def _terminate_process_tree(process: subprocess.Popen[bytes], job: _ProcessTreeJob | None) -> None:
    """Terminate a child process and its descendants cleanly across Windows and POSIX."""
    if getattr(process, "_handle", None) is None and os.name == "nt":
        process.kill()
        try:
            process.wait(timeout=3.0)
        except BaseException:
            pass
        return
    if process.poll() is not None:
        return
    if os.name == "nt":
        if job is not None and job.terminate():
            try:
                process.wait(timeout=3.0)
                return
            except subprocess.TimeoutExpired:
                pass
        taskkill = shutil.which("taskkill")
        if taskkill:
            subprocess.run(
                [taskkill, "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                check=False,
                timeout=5.0,
            )
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            pass
        return

    killpg = getattr(os, "killpg", None)
    getpgid = getattr(os, "getpgid", None)
    sigkill = getattr(signal, "SIGKILL", None)
    try:
        if killpg is not None and getpgid is not None and sigkill is not None:
            killpg(getpgid(process.pid), sigkill)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        pass


def run_supervised_subprocess(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout_seconds: float = 60.0,
    max_output_bytes: int = 4_194_304,
    env_allowlist: frozenset[str] = DEFAULT_ENV_ALLOWLIST,
    extra_env: dict[str, str] | None = None,
    input_bytes: bytes | None = None,
    cancellation: threading.Event | None = None,
    deadline_at: float | None = None,
    popen_factory: Any = None,
) -> SupervisedProcessResult:
    """Execute a subprocess under strict timeout, output-size, and tree-cleanup controls."""
    if not command or not isinstance(command, list):
        raise SubprocessExecutionError(
            "SUBPROCESS_INVALID_COMMAND", "Command must be a non-empty list."
        )
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive.")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive.")

    executable = resolve_executable(command[0])
    args = [executable, *command[1:]]
    env = {key: value for key, value in os.environ.items() if key.upper() in env_allowlist}
    if extra_env:
        env.update(extra_env)

    started = time.monotonic()
    effective_deadline = started + float(timeout_seconds)
    if deadline_at is not None:
        effective_deadline = min(effective_deadline, float(deadline_at))
    if effective_deadline <= started:
        raise ExecutionDeadlineExceeded(
            "EXECUTION_DEADLINE_EXCEEDED",
            "Execution deadline already expired before subprocess launch.",
        )
    if cancellation is not None and cancellation.is_set():
        raise SubprocessExecutionError(
            "SUBPROCESS_CANCELLED", "Subprocess cancelled before launch."
        )

    process: subprocess.Popen[bytes] | None = None
    job = _ProcessTreeJob()
    stdout = bytearray()
    stderr = bytearray()
    exceeded = threading.Event()
    total_lock = threading.Lock()
    total_bytes = 0

    def drain(pipe: BinaryIO, buffer: bytearray) -> None:
        nonlocal total_bytes
        try:
            while chunk := pipe.read(8192):
                with total_lock:
                    remaining = max(0, max_output_bytes - total_bytes)
                    if len(chunk) > remaining:
                        if remaining > 0:
                            buffer.extend(chunk[:remaining])
                            total_bytes += remaining
                        exceeded.set()
                        if process is not None:
                            _terminate_process_tree(process, job)
                        break
                    buffer.extend(chunk)
                    total_bytes += len(chunk)
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )

    threads: list[threading.Thread] = []
    try:
        popen_kwargs: dict[str, object] = {
            "cwd": str(cwd) if cwd is not None else None,
            "stdin": subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
            "env": env,
            "close_fds": True,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = creationflags
        else:
            popen_kwargs["start_new_session"] = True

        launcher = popen_factory or subprocess.Popen
        process = launcher(args, **popen_kwargs)  # type: ignore[call-overload]
        job.assign(process)

        if input_bytes is not None and process.stdin is not None:
            try:
                process.stdin.write(input_bytes)
            except OSError:
                pass
            finally:
                process.stdin.close()

        assert process.stdout is not None and process.stderr is not None
        threads = [
            threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
        ]
        for thread in threads:
            thread.start()

        while True:
            if cancellation is not None and cancellation.is_set():
                _terminate_process_tree(process, job)
                raise SubprocessExecutionError(
                    "SUBPROCESS_CANCELLED", "Subprocess terminated due to cancellation."
                )
            now = time.monotonic()
            remaining = effective_deadline - now
            if remaining <= 0:
                _terminate_process_tree(process, job)
                if deadline_at is not None and effective_deadline == float(deadline_at):
                    raise ExecutionDeadlineExceeded(
                        "EXECUTION_DEADLINE_EXCEEDED",
                        "Subprocess terminated because job deadline expired.",
                    )
                raise SubprocessExecutionError(
                    "SUBPROCESS_TIMEOUT",
                    "Subprocess exceeded its configured timeout.",
                )
            try:
                returncode = process.wait(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
            except BaseException:
                _terminate_process_tree(process, job)
                raise

        for thread in threads:
            thread.join(timeout=2.0)

        if exceeded.is_set():
            raise SubprocessExecutionError(
                "SUBPROCESS_OUTPUT_LIMIT_EXCEEDED",
                "Subprocess exceeded the configured output limit.",
            )
        return SupervisedProcessResult(
            returncode=returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            duration_seconds=max(0.0, time.monotonic() - started),
        )
    except OSError as exc:
        if process is not None:
            _terminate_process_tree(process, job)
        raise SubprocessExecutionError(
            "SUBPROCESS_START_FAILED", "Subprocess could not be started."
        ) from exc
    finally:
        if process is not None and process.poll() is None:
            _terminate_process_tree(process, job)
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=1.0)
        job.close()
