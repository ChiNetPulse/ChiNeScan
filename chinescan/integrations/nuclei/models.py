"""Strict normalized Nuclei result models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class NucleiFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    template_id: str = Field(min_length=1, max_length=160)
    name: str = Field(min_length=1, max_length=240)
    severity: str = Field(min_length=1, max_length=32)
    matched_at: str = Field(min_length=1, max_length=2048)
    matcher_name: str | None = Field(default=None, max_length=120)
    template_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class NucleiScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target: str = Field(min_length=1, max_length=2048)
    findings: tuple[NucleiFinding, ...] = Field(max_length=5000)
    finding_count: int = Field(ge=0, le=5000)
    tool_version: str = Field(min_length=1, max_length=80)
    finished_at: str
