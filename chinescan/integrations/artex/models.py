"""Local typed records for health observations and append-only audit events."""

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class ArtexHealth(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ok: bool
    service: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=128)


class ArtexAuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(default_factory=lambda: "artex:audit:" + str(uuid4()))
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: Literal[
        "health_requested", "health_succeeded", "health_failed", "configuration_rejected"
    ]
    outcome: Literal["started", "success", "unavailable", "invalid", "blocked"]
    correlation_id: str = Field(min_length=1, max_length=128)
    operator_id: str | None = Field(default=None, max_length=255)
    configured_release_id: str | None = Field(default=None, max_length=128)
    upstream_version: str | None = Field(default=None, max_length=128)
    error_code: str | None = Field(default=None, max_length=64)


class ArtexSyncState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str = "artex:sync:health"
    state: Literal["disabled", "unknown", "available", "unavailable", "invalid"]
    checked_at: datetime | None = None
    health: ArtexHealth | None = None
    error_code: str | None = None


class ArtexInstanceProfile(BaseModel):
    """Secret-free profile projection; credential fields are forbidden."""

    model_config = ConfigDict(extra="forbid")
    instance_id: str = Field(pattern=r"^artex:[a-zA-Z0-9_-]{1,64}$")
    release_id: str = Field(min_length=1, max_length=128)
    base_url: str
    enabled: bool = False
    mode: Literal["disabled", "health_only"] = "disabled"


class ArtexTaskReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str = Field(pattern=r"^artex:task:[^:]{1,200}$")
    instance_id: str
    external_task_id: str = Field(min_length=1, max_length=200)
    external_status: str | None = None
    observed_at: datetime


class ArtexFindingReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str = Field(pattern=r"^artex:finding:[^:]{1,200}$")
    instance_id: str
    external_task_id: str
    external_finding_id: str
    provenance_state: Literal["unverified"] = "unverified"
    content_digest: str | None = None
    observed_at: datetime
