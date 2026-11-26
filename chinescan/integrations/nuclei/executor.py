"""No-shell, bounded Nuclei process execution."""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from chinescan.core.execution_isolation import IsolationProfile
from chinescan.core.subprocess_supervision import (
    SubprocessExecutionError,
    run_supervised_subprocess,
)
from chinescan.integrations.nuclei.models import NucleiScanResult
from chinescan.integrations.nuclei.parser import NucleiParseError, parse_nuclei_jsonl
from chinescan.integrations.nuclei.profiles import NUCLEI_PROFILES, validate_parameters


class NucleiExecutionError(RuntimeError):
    """Safe stable execution failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass
class NucleiExecutor:
    binary: str = "nuclei"
    template_directory: Path | None = None
    approved_templates: dict[str, str] | None = None
    timeout_seconds: float = 120.0
    max_output_bytes: int = 8_388_608
    expected_major: int | None = None
    isolation_profile: IsolationProfile | None = None
    require_hardened_isolation: bool = True

    def check_available(self) -> str:
        try:
            completed = subprocess.run(
                [self.binary, "-version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                timeout=min(self.timeout_seconds, 10.0),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise NucleiExecutionError("nuclei_unavailable") from None
        output = completed.stdout[:4096].decode("utf-8", errors="replace")
        match = re.search(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", output)
        if completed.returncode != 0 or match is None:
            raise NucleiExecutionError("nuclei_version_invalid")
        major = int(match.group(1))
        if self.expected_major is not None and major != self.expected_major:
            raise NucleiExecutionError("nuclei_version_unsupported")
        if self.template_directory is None or not self.template_directory.is_dir():
            raise NucleiExecutionError("nuclei_templates_unavailable")
        return match.group(0)[:80]

    def _template_path(self, template_id: str) -> str:
        if self.template_directory is None or self.approved_templates is None:
            raise NucleiExecutionError("nuclei_templates_unavailable")
        relative = Path(template_id)
        if relative.is_absolute() or ".." in relative.parts or relative.name != template_id:
            raise NucleiExecutionError("nuclei_template_invalid")
        candidate = (self.template_directory / relative).resolve()
        root = self.template_directory.resolve()
        if root not in candidate.parents or not candidate.is_file():
            raise NucleiExecutionError("nuclei_template_unavailable")
        expected = (self.approved_templates or {}).get(template_id)
        if expected is None or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
            raise NucleiExecutionError("nuclei_template_hash_invalid")
        digest = hashlib.sha256()
        try:
            with candidate.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1_048_576), b""):
                    digest.update(chunk)
        except OSError:
            raise NucleiExecutionError("nuclei_template_unavailable") from None
        if digest.hexdigest().lower() != expected.lower():
            raise NucleiExecutionError("nuclei_template_integrity_failed")
        return str(candidate)

    def run(self, *, target: str, parameters: dict[str, object]) -> NucleiScanResult:
        try:
            normalized = validate_parameters(parameters, self.approved_templates or {})
        except ValueError:
            raise NucleiExecutionError("nuclei_parameters_invalid") from None
        version = self.check_available()
        profile = NUCLEI_PROFILES[normalized["profile"]]
        args = [
            "-jsonl",
            "-silent",
            "-no-color",
            "-rate-limit",
            str(profile.rate_limit),
            "-timeout",
            str(profile.timeout_seconds),
        ]
        for template_id in normalized["templates"]:
            args.extend(("-t", self._template_path(template_id)))
        args.extend(("-target", target))
        try:
            result = run_supervised_subprocess(
                [self.binary, *args],
                timeout_seconds=self.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                isolation_profile=self.isolation_profile,
                require_hardened_isolation=self.require_hardened_isolation,
            )
        except SubprocessExecutionError as exc:
            mapping = {
                "SUBPROCESS_TIMEOUT": "nuclei_timeout",
                "SUBPROCESS_OUTPUT_LIMIT_EXCEEDED": "nuclei_output_too_large",
                "SUBPROCESS_START_FAILED": "nuclei_unavailable",
            }
            raise NucleiExecutionError(mapping.get(exc.code, "nuclei_failed")) from None
        if result.returncode != 0:
            raise NucleiExecutionError("nuclei_failed")
        try:
            return parse_nuclei_jsonl(
                result.stdout, target=target, tool_version=version, max_bytes=self.max_output_bytes
            )
        except NucleiParseError as exc:
            raise NucleiExecutionError(str(exc)) from None
