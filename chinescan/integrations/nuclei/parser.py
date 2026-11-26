"""Bounded parser for Nuclei JSONL output."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from chinescan.integrations.nuclei.models import NucleiFinding, NucleiScanResult


class NucleiParseError(ValueError):
    """Nuclei output is malformed, hostile, or exceeds configured bounds."""


def parse_nuclei_jsonl(
    raw: bytes,
    *,
    target: str,
    tool_version: str,
    max_bytes: int = 8_388_608,
    max_findings: int = 5000,
) -> NucleiScanResult:
    if not raw or len(raw) > max_bytes:
        raise NucleiParseError("nuclei_output_invalid")
    findings: list[NucleiFinding] = []
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise NucleiParseError("nuclei_output_invalid") from None
    for line in lines:
        if not line.strip():
            continue
        if len(findings) >= max_findings:
            raise NucleiParseError("nuclei_finding_limit_exceeded")
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            raise NucleiParseError("nuclei_output_invalid") from None
        if not isinstance(item, dict):
            raise NucleiParseError("nuclei_output_invalid")
        info = item.get("info")
        if not isinstance(info, dict):
            raise NucleiParseError("nuclei_output_invalid")
        template_id = item.get("template-id")
        matched_at = item.get("matched-at") or item.get("host")
        name = info.get("name")
        severity = info.get("severity")
        if not all(
            isinstance(value, str) and value for value in (template_id, matched_at, name, severity)
        ):
            raise NucleiParseError("nuclei_output_invalid")
        assert isinstance(template_id, str)
        assert isinstance(matched_at, str)
        assert isinstance(name, str)
        assert isinstance(severity, str)
        matcher_name = item.get("matcher-name")
        if not isinstance(matcher_name, str):
            matcher_name = None
        findings.append(
            NucleiFinding(
                template_id=template_id[:160],
                name=name[:240],
                severity=severity[:32],
                matched_at=matched_at[:2048],
                matcher_name=matcher_name[:120] if matcher_name else None,
            )
        )
    return NucleiScanResult(
        target=target,
        findings=tuple(findings),
        finding_count=len(findings),
        tool_version=tool_version,
        finished_at=datetime.now(UTC).isoformat(),
    )
