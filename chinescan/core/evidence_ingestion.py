"""Common, tenant-scoped evidence ingestion for governed scanner adapters."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.storage.sqlite import SQLiteRepository

if TYPE_CHECKING:
    from chinescan.core.execution_adapters import ExecutionContext


class EvidenceIngestionError(ValueError):
    """Raised when normalized evidence cannot be safely persisted."""


class EvidenceEnvelope(BaseModel):
    """Immutable metadata recorded with every normalized scanner result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_type: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_.-]*$")
    source_format: str = Field(min_length=1, max_length=32)
    parser_version: str = Field(min_length=1, max_length=64)
    tool: str = Field(min_length=1, max_length=64)
    tool_version: str = Field(min_length=1, max_length=80)
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    job_id: str = Field(min_length=36, max_length=36)
    organization_id: str = Field(min_length=36, max_length=36)
    engagement_id: str = Field(min_length=36, max_length=36)
    scope_revision_id: str = Field(min_length=36, max_length=36)
    target: str = Field(min_length=1, max_length=2048)
    collected_at: str
    ingested_at: str
    retention_until: str


class EvidenceIngestionService:
    """Persist bounded, canonical, idempotent evidence through the repository."""

    def __init__(self, repository: SQLiteRepository, *, retention_days: int = 365) -> None:
        self.repository = repository
        if not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")
        self.retention_days = retention_days

    @staticmethod
    def _canonical_bytes(payload: dict[str, Any]) -> bytes:
        try:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise EvidenceIngestionError("evidence_payload_invalid") from exc
        if len(encoded.encode("utf-8")) > 33_554_432:
            raise EvidenceIngestionError("evidence_payload_too_large")
        return encoded.encode("utf-8")

    def ingest(
        self,
        context: ExecutionContext,
        *,
        evidence_type: str,
        source_format: str,
        parser_version: str,
        tool: str,
        tool_version: str,
        payload: dict[str, Any],
        collected_at: str | None = None,
    ) -> tuple[str, EvidenceEnvelope]:
        canonical = self._canonical_bytes(payload)
        digest = hashlib.sha256(canonical).hexdigest()
        record_id = str(uuid5(NAMESPACE_URL, f"chinescan-evidence:{context.job_id}:{digest}"))
        now = datetime.now(UTC).isoformat()
        retention_until = (datetime.now(UTC) + timedelta(days=self.retention_days)).isoformat()
        envelope = EvidenceEnvelope(
            evidence_type=evidence_type,
            source_format=source_format,
            parser_version=parser_version,
            tool=tool,
            tool_version=tool_version,
            content_sha256=digest,
            job_id=context.job_id,
            organization_id=context.organization_id,
            engagement_id=context.engagement_id,
            scope_revision_id=context.scope_revision_id,
            target=context.target,
            collected_at=collected_at or now,
            ingested_at=now,
            retention_until=retention_until,
        )
        record = {
            **payload,
            **envelope.model_dump(mode="json"),
            "record_id": record_id,
            "evidence_type": evidence_type,
        }
        with self.repository.member_context(
            context.organization_id, context.requester_user_id, write=True
        ):
            with self.repository.execution_provenance_context(context.model_dump(mode="json")):
                existing = self.repository.get("evidence", record_id)
                if existing is None:
                    self.repository.save("evidence", record_id, record)
                elif existing.get("content_sha256") != digest:
                    raise EvidenceIngestionError("evidence_id_collision")
        return record_id, envelope
