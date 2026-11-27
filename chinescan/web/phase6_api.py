"""Authenticated API for Phase 6 isolation and evidence lifecycle operations."""

# FastAPI dependency injection intentionally uses Depends in endpoint defaults.
# ruff: noqa: B008

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.accounts import Session
from chinescan.core.errors import StorageError
from chinescan.core.phase6_governance import (
    EvidenceLifecycleService,
    Phase6PolicyError,
    probe_capabilities,
)


class RetentionPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retention_days: int = Field(ge=1, le=36500)
    engagement_id: str | None = Field(default=None, min_length=36, max_length=36)
    evidence_category: str | None = Field(default=None, min_length=1, max_length=80)


class LegalHoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=500)
    records: list[tuple[str, str]] = Field(min_length=1, max_length=1000)
    engagement_id: str | None = Field(default=None, min_length=36, max_length=36)


def create_phase6_router(repository: Any, current_session: Any, require_csrf: Any) -> APIRouter:
    router = APIRouter(prefix="/api/organizations/{organization_id}/phase6", tags=["phase6"])
    lifecycle = EvidenceLifecycleService(repository)

    def actor(session: Session) -> str:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session.user_id

    @router.get("/status")
    def status(organization_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        user_id = actor(session)
        try:
            with repository.member_context(organization_id, user_id):
                snapshot = probe_capabilities()
                return {
                    "platform": snapshot.platform,
                    "profile": snapshot.profile,
                    "policy_version": snapshot.policy_version,
                    "hardened_enforced": snapshot.hardened,
                    "required_controls": list(snapshot.required_controls),
                    "enforced_controls": list(snapshot.enforced_controls),
                    "unavailable_controls": list(snapshot.unavailable_controls),
                }
        except Exception:
            raise HTTPException(status_code=404, detail="Organization not found.") from None

    @router.get("/retention/policies")
    def policies(
        organization_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        try:
            return {"items": lifecycle.list_policies(organization_id, actor(session))}
        except StorageError:
            raise HTTPException(status_code=404, detail="Organization not found.") from None

    @router.post("/retention/policies", status_code=201, dependencies=[Depends(require_csrf)])
    def create_policy(
        organization_id: str,
        payload: RetentionPolicyRequest,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            policy_id = lifecycle.create_policy(
                organization_id,
                actor(session),
                payload.retention_days,
                engagement_id=payload.engagement_id,
                evidence_category=payload.evidence_category,
            )
        except Phase6PolicyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"id": policy_id}

    @router.get("/legal-holds")
    def holds(organization_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        try:
            return {"items": lifecycle.list_holds(organization_id, actor(session))}
        except StorageError:
            raise HTTPException(status_code=404, detail="Organization not found.") from None

    @router.post("/legal-holds", status_code=201, dependencies=[Depends(require_csrf)])
    def create_hold(
        organization_id: str,
        payload: LegalHoldRequest,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            hold_id = lifecycle.create_hold(
                organization_id,
                actor(session),
                payload.records,
                payload.reason,
                engagement_id=payload.engagement_id,
            )
        except Phase6PolicyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"id": hold_id}

    @router.post("/legal-holds/{hold_id}/release", dependencies=[Depends(require_csrf)])
    def release_hold(
        organization_id: str,
        hold_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        if not lifecycle.release_hold(organization_id, actor(session), hold_id):
            raise HTTPException(status_code=404, detail="Legal hold not found.")
        return {"id": hold_id, "status": "released"}

    @router.get("/retention/jobs")
    def jobs(organization_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        try:
            return {"items": lifecycle.list_retention_jobs(organization_id, actor(session))}
        except StorageError:
            raise HTTPException(status_code=404, detail="Organization not found.") from None

    @router.get("/retention/audit")
    def audit(organization_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        try:
            return {"items": lifecycle.list_audit(organization_id, actor(session))}
        except StorageError:
            raise HTTPException(status_code=404, detail="Organization not found.") from None

    return router
