"""Authenticated API for local repository assets and governed assessments."""

# FastAPI dependency injection intentionally uses Depends in endpoint defaults.
# ruff: noqa: B008

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.accounts import Session
from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker
from chinescan.core.repository_assessment import (
    ATTESTATION_TEXT,
    RepositoryAssessmentService,
    RepositorySnapshotError,
)


class RepositoryAssetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str | None = Field(default=None, max_length=2000)


class RepositoryBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_registry_id: str = Field(min_length=1, max_length=80)
    authorization_id: str = Field(min_length=36, max_length=36)
    scope_revision_id: str = Field(min_length=36, max_length=36)
    attestation_text: str = Field(min_length=1, max_length=1000)


class RepositoryExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=36, max_length=36)
    idempotency_key: str = Field(min_length=16, max_length=80)


class SnapshotHoldRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=500)


class SnapshotDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: str = Field(pattern=r"^DELETE SNAPSHOT$")


def create_repository_router(
    service: RepositoryAssessmentService,
    governance: ExecutionGovernanceService,
    worker: GovernedDomainWorker,
    current_session: Any,
    require_csrf: Any,
) -> APIRouter:
    router = APIRouter(
        prefix="/api/organizations/{organization_id}/engagements/{engagement_id}/repositories",
        tags=["governed-repository-assessment"],
    )

    def principal(session: Session) -> str:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session.user_id

    def map_error(exc: RepositorySnapshotError) -> HTTPException:
        status = 413 if exc.code in {"snapshot_too_large", "snapshot_file_limit", "snapshot_depth_limit", "organization_quota_exceeded"} else 422
        return HTTPException(status_code=status, detail={"code": exc.code, "message": str(exc)})

    @router.get("/projects")
    def projects(organization_id: str, engagement_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        result = service.projects_for(principal(session), organization_id, engagement_id)
        if result is None:
            if service.list_assets(principal(session), organization_id, engagement_id) is None:
                raise HTTPException(status_code=404, detail="Engagement not found.")
            return {"items": []}
        return {"items": result}

    @router.get("")
    def list_assets(organization_id: str, engagement_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        result = service.list_assets(principal(session), organization_id, engagement_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        return {"items": result}

    @router.get("/quota")
    def quota(organization_id: str, engagement_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        result = service.quota(principal(session), organization_id, engagement_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        return result

    @router.get("/retention")
    def retention_status(organization_id: str, engagement_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        result = service.retention_candidates(principal(session), organization_id, engagement_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        return {"items": result}

    @router.post("", status_code=201, dependencies=[Depends(require_csrf)])
    def create_asset(organization_id: str, engagement_id: str, payload: RepositoryAssetRequest, session: Session = Depends(current_session)) -> dict[str, Any]:
        try:
            result = service.create_asset(principal(session), organization_id, engagement_id, payload.description)
        except RepositorySnapshotError as exc:
            raise map_error(exc) from None
        if result is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        return result

    @router.post("/{asset_id}/bind", status_code=201, dependencies=[Depends(require_csrf)])
    def bind(organization_id: str, engagement_id: str, asset_id: str, payload: RepositoryBindingRequest, session: Session = Depends(current_session)) -> dict[str, Any]:
        try:
            result = service.bind(principal(session), organization_id, engagement_id, asset_id,
                                  payload.project_registry_id, payload.authorization_id,
                                  payload.scope_revision_id, payload.attestation_text)
        except RepositorySnapshotError as exc:
            raise map_error(exc) from None
        if result is None:
            raise HTTPException(status_code=404, detail="Repository asset not found.")
        return result

    @router.post("/executions", status_code=202, dependencies=[Depends(require_csrf)])
    def create_execution(organization_id: str, engagement_id: str, payload: RepositoryExecutionRequest, session: Session = Depends(current_session)) -> dict[str, Any]:
        asset = service.get_asset(principal(session), organization_id, engagement_id, payload.asset_id)
        if asset is None or not asset.get("binding_id") or not asset.get("attestation_id"):
            raise HTTPException(status_code=404, detail="Repository asset not found.")
        try:
            result = governance.create_governed_job(
                principal(session), organization_id, engagement_id, payload.asset_id,
                technique="repository_code_assessment", approval_id=None,
                idempotency_key=payload.idempotency_key,
                repository_binding_id=asset["binding_id"],
                repository_attestation_id=asset["attestation_id"],
            )
        except OverflowError:
            raise HTTPException(status_code=429, detail={"code": "execution_queue_full", "message": "Execution queue is full."}) from None
        if result.get("decision") == "DENY":
            raise HTTPException(status_code=403, detail={"code": result.get("reason_code", "policy_denied"), "message": result.get("explanation", "Execution was denied by policy.")})
        return result

    @router.get("/{asset_id}/retention")
    def retention(organization_id: str, engagement_id: str, asset_id: str, session: Session = Depends(current_session)) -> dict[str, Any]:
        asset = service.get_asset(principal(session), organization_id, engagement_id, asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Repository asset not found.")
        return {"items": service.retention_candidates(principal(session), organization_id, engagement_id) or []}

    @router.post("/snapshots/{snapshot_id}/hold", dependencies=[Depends(require_csrf)])
    def hold(organization_id: str, engagement_id: str, snapshot_id: str, payload: SnapshotHoldRequest, session: Session = Depends(current_session)) -> dict[str, Any]:
        if not service.snapshots.hold(principal(session), organization_id, engagement_id, snapshot_id, payload.reason):
            raise HTTPException(status_code=404, detail="Snapshot not found.")
        return {"snapshot_id": snapshot_id, "held": True}

    @router.delete("/snapshots/{snapshot_id}/hold", dependencies=[Depends(require_csrf)])
    def release_hold(organization_id: str, engagement_id: str, snapshot_id: str, payload: SnapshotHoldRequest, session: Session = Depends(current_session)) -> dict[str, Any]:
        if not service.snapshots.release_hold(principal(session), organization_id, engagement_id, snapshot_id, payload.reason):
            raise HTTPException(status_code=404, detail="Snapshot not found.")
        return {"snapshot_id": snapshot_id, "held": False}

    @router.post("/snapshots/{snapshot_id}/delete", dependencies=[Depends(require_csrf)])
    def delete_snapshot(organization_id: str, engagement_id: str, snapshot_id: str, payload: SnapshotDeleteRequest, session: Session = Depends(current_session)) -> dict[str, Any]:
        try:
            if payload.confirmation != "DELETE SNAPSHOT":
                raise HTTPException(status_code=422, detail={"code": "confirmation_required", "message": "Explicit snapshot deletion confirmation is required."})
            if not service.snapshots.delete_eligible(principal(session), organization_id, engagement_id, snapshot_id):
                raise HTTPException(status_code=404, detail="Snapshot not found.")
        except RepositorySnapshotError as exc:
            raise map_error(exc) from None
        return {"snapshot_id": snapshot_id, "status": "deleted"}

    @router.get("/attestation")
    def attestation_text(organization_id: str, engagement_id: str, _session: Session = Depends(current_session)) -> dict[str, str]:
        if service.list_assets(principal(_session), organization_id, engagement_id) is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        return {"version": "repository-code-authorization-v1", "text": ATTESTATION_TEXT}

    return router
