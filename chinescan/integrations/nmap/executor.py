"""Bounded no-shell Nmap process execution."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from threading import Event, Thread

from chinescan.core.execution_isolation import IsolationProfile, require_isolation
from chinescan.core.subprocess_supervision import (
    SubprocessExecutionError,
    run_supervised_subprocess,
)
from chinescan.integrations.nmap.models import NmapProfileName, NmapScanResult
from chinescan.integrations.nmap.parser import NmapParseError, parse_nmap_xml
from chinescan.integrations.nmap.profiles import build_nmap_arguments


class NmapExecutionError(RuntimeError):
    """Safe, stable execution failure code without host/process detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class NmapExecutionTelemetry:
    """Safe operational measurements; no command or environment details."""

    duration_seconds: float
    output_bytes: int
    returncode: int
    termination_reason: str | None = None


@dataclass
class NmapExecutor:
    binary: str = "nmap"
    timeout_seconds: float = 60.0
    max_output_bytes: int = 4_194_304
    expected_major: int | None = None
    isolation_profile: IsolationProfile | None = None
    require_hardened_isolation: bool = False
    last_telemetry: NmapExecutionTelemetry | None = field(default=None, init=False)

    def check_available(self) -> str:
        if self.require_hardened_isolation:
            if self.isolation_profile is None:
                raise NmapExecutionError("isolation_unavailable")
            try:
                require_isolation(self.isolation_profile)
            except Exception:
                raise NmapExecutionError("isolation_unavailable") from None
        try:
            completed = subprocess.run(
                [self.binary, "--version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                timeout=min(self.timeout_seconds, 10.0),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise NmapExecutionError("nmap_unavailable") from None
        output = completed.stdout[:4096].decode("utf-8", errors="replace")
        match = re.search(r"Nmap version (\d+)(?:\.(\d+))?", output)
        if completed.returncode != 0 or match is None:
            raise NmapExecutionError("nmap_version_invalid")
        major = int(match.group(1))
        if self.expected_major is not None and major != self.expected_major:
            raise NmapExecutionError("nmap_version_unsupported")
        return match.group(0).replace("Nmap version ", "")[:80]

    def run(
        self,
        *,
        target: str,
        profile: NmapProfileName,
        ports: list[int] | None = None,
    ) -> NmapScanResult:
        args = build_nmap_arguments(profile, target, ports=ports)
        try:
            version = self.check_available()
            if self.require_hardened_isolation:
                if self.isolation_profile is None:
                    raise NmapExecutionError("isolation_unavailable")
                try:
                    result = run_supervised_subprocess(
                        [self.binary, *args],
                        timeout_seconds=self.timeout_seconds,
                        max_output_bytes=self.max_output_bytes,
                        isolation_profile=self.isolation_profile,
                        require_hardened_isolation=True,
                    )
                except SubprocessExecutionError as exc:
                    mapping = {
                        "SUBPROCESS_TIMEOUT": "nmap_timeout",
                        "SUBPROCESS_OUTPUT_LIMIT_EXCEEDED": "nmap_output_too_large",
                        "SUBPROCESS_CANCELLED": "nmap_cancelled",
                        "SUBPROCESS_START_FAILED": "nmap_unavailable",
                    }
                    raise NmapExecutionError(mapping.get(exc.code, "nmap_failed")) from None
                self.last_telemetry = NmapExecutionTelemetry(
                    duration_seconds=result.duration_seconds,
                    output_bytes=len(result.stdout),
                    returncode=result.returncode,
                )
                if result.returncode != 0:
                    raise NmapExecutionError("nmap_failed")
                try:
                    return parse_nmap_xml(
                        result.stdout,
                        profile=profile,
                        target=target,
                        max_bytes=self.max_output_bytes,
                    ).model_copy(update={"nmap_version": version})
                except NmapParseError as exc:
                    raise NmapExecutionError(str(exc)) from None
            process = subprocess.Popen(
                [self.binary, *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
            output = bytearray()
            overflow = Event()

            def drain_output() -> None:
                if process.stdout is None:
                    return
                while True:
                    chunk = process.stdout.read(64 * 1024)
                    if not chunk:
                        return
                    if len(output) + len(chunk) > self.max_output_bytes:
                        overflow.set()
                        process.kill()
                        return
                    output.extend(chunk)

            reader = Thread(target=drain_output, name="chinescan-nmap-output", daemon=True)
            reader.start()
            try:
                return_code = process.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                reader.join(timeout=5)
                raise NmapExecutionError("nmap_timeout") from None
            reader.join(timeout=5)
            if reader.is_alive():
                process.kill()
                reader.join(timeout=5)
                raise NmapExecutionError("nmap_output_unreadable")
        except NmapExecutionError:
            raise
        except OSError:
            raise NmapExecutionError("nmap_unavailable") from None
        if overflow.is_set():
            raise NmapExecutionError("nmap_output_too_large")
        self.last_telemetry = NmapExecutionTelemetry(
            duration_seconds=0.0,
            output_bytes=len(output),
            returncode=return_code,
            termination_reason="output_limit" if overflow.is_set() else None,
        )
        if return_code != 0:
            raise NmapExecutionError("nmap_failed")
        try:
            return parse_nmap_xml(
                bytes(output),
                profile=profile,
                target=target,
                max_bytes=self.max_output_bytes,
            ).model_copy(update={"nmap_version": version})
        except NmapParseError as exc:
            raise NmapExecutionError(str(exc)) from None
