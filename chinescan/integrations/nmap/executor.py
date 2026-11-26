"""Bounded no-shell Nmap process execution."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from threading import Event, Thread

from chinescan.integrations.nmap.models import NmapProfileName, NmapScanResult
from chinescan.integrations.nmap.parser import NmapParseError, parse_nmap_xml
from chinescan.integrations.nmap.profiles import build_nmap_arguments


class NmapExecutionError(RuntimeError):
    """Safe, stable execution failure code without host/process detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class NmapExecutor:
    binary: str = "nmap"
    timeout_seconds: float = 60.0
    max_output_bytes: int = 4_194_304
    expected_major: int | None = None

    def check_available(self) -> str:
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
