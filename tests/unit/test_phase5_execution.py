from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from chinescan.core.evidence_ingestion import EvidenceIngestionError, EvidenceIngestionService
from chinescan.core.execution_isolation import (
    IsolationProfile,
    IsolationUnavailableError,
    isolation_status,
    require_isolation,
)
from chinescan.integrations.nmap.executor import NmapExecutionError, NmapExecutor
from chinescan.integrations.nuclei.executor import NucleiExecutionError, NucleiExecutor
from chinescan.integrations.nuclei.parser import NucleiParseError, parse_nuclei_jsonl
from chinescan.integrations.nuclei.profiles import validate_parameters


def test_hardened_isolation_reports_platform_capability() -> None:
    status = isolation_status()
    assert status["platform"]
    assert status["hardened_supported"] is False
    with pytest.raises(IsolationUnavailableError):
        require_isolation(IsolationProfile(cpu_seconds=1, memory_bytes=32_000_000))


def test_nmap_hardened_mode_fails_closed_when_unavailable() -> None:
    with pytest.raises(NmapExecutionError, match="isolation_unavailable"):
        NmapExecutor(require_hardened_isolation=True).check_available()


def test_nuclei_profiles_reject_arbitrary_templates() -> None:
    with pytest.raises(ValueError):
        validate_parameters({"profile": "safe_web_checks", "templates": ["../escape.yaml"]}, {})


def test_nuclei_parser_is_bounded_and_normalized() -> None:
    raw = (
        b'{"template-id":"x-001","info":{"name":"Example","severity":"low"},'
        b'"matched-at":"192.0.2.10"}\n'
    )
    result = parse_nuclei_jsonl(raw, target="192.0.2.10", tool_version="3.3.0", max_bytes=4096)
    assert result.finding_count == 1
    assert result.findings[0].template_id == "x-001"
    with pytest.raises(NucleiParseError):
        parse_nuclei_jsonl(raw, target="192.0.2.10", tool_version="3.3.0", max_bytes=8)


def test_nuclei_template_hash_is_verified(tmp_path) -> None:
    template = tmp_path / "x.yaml"
    template.write_text("id: x-001\n", encoding="utf-8")
    executor = NucleiExecutor(
        template_directory=tmp_path,
        approved_templates={"x.yaml": "0" * 64},
    )
    with pytest.raises(NucleiExecutionError, match="integrity_failed"):
        executor._template_path("x.yaml")


class _EvidenceRepository:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, object]] = {}

    def member_context(self, *_args: object, **_kwargs: object):
        return nullcontext()

    def execution_provenance_context(self, *_args: object, **_kwargs: object):
        return nullcontext()

    def get(self, _record_type: str, record_id: str):
        return self.records.get(record_id)

    def save(self, _record_type: str, record_id: str, payload: dict[str, object]) -> None:
        self.records[record_id] = payload


def test_evidence_ingestion_is_canonical_idempotent_and_tenant_bound() -> None:
    repository = _EvidenceRepository()
    service = EvidenceIngestionService(repository)  # type: ignore[arg-type]
    context = SimpleNamespace(
        job_id="11111111-1111-4111-8111-111111111111",
        organization_id="22222222-2222-4222-8222-222222222222",
        requester_user_id="33333333-3333-4333-8333-333333333333",
        engagement_id="44444444-4444-4444-8444-444444444444",
        scope_revision_id="55555555-5555-4555-8555-555555555555",
        target="192.0.2.10",
        model_dump=lambda mode=None: {"job_id": "11111111-1111-4111-8111-111111111111"},
    )
    record_id, envelope = service.ingest(
        context,
        evidence_type="nmap_result",
        source_format="json",
        parser_version="test-v1",
        tool="nmap",
        tool_version="8.0",
        payload={"result": {"hosts": []}},
    )
    repeat_id, repeat = service.ingest(
        context,
        evidence_type="nmap_result",
        source_format="json",
        parser_version="test-v1",
        tool="nmap",
        tool_version="8.0",
        payload={"result": {"hosts": []}},
    )
    assert repeat_id == record_id
    assert repeat.content_sha256 == envelope.content_sha256
    assert repository.records[record_id]["organization_id"] == context.organization_id
    repository.records[record_id]["content_sha256"] = "0" * 64
    with pytest.raises(EvidenceIngestionError, match="collision"):
        service.ingest(
            context,
            evidence_type="nmap_result",
            source_format="json",
            parser_version="test-v1",
            tool="nmap",
            tool_version="8.0",
            payload={"result": {"hosts": []}},
        )
