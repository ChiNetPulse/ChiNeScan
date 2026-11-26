"""Authenticated API for the disabled-by-default governed Nuclei adapter."""

# FastAPI dependency injection intentionally uses Depends in endpoint defaults.
# ruff: noqa: B008

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.accounts import Session
from chinescan.core.config.settings import NucleiIntegrationSettings
from chinescan.core.execution_governance import ExecutionGovernanceService
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.integrations.nuclei.profiles import profile_listing


class NucleiExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=36, max_length=36)
    profile: str = Field(min_length=1, max_length=64)
    templates: list[str] = Field(min_length=1, max_length=32)
    approval_id: str | None = Field(default=None, min_length=36, max_length=36)
    idempotency_key: str = Field(min_length=16, max_length=80)


def create_nuclei_router(
    governance: ExecutionGovernanceService,
    repository: SQLiteRepository,
    settings: NucleiIntegrationSettings,
    current_session: Any,
    require_csrf: Any,
) -> APIRouter:
    router = APIRouter(
        prefix="/api/organizations/{organization_id}/engagements/{engagement_id}/nuclei",
        tags=["governed-nuclei"],
    )

    def principal(session: Session) -> str:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session.user_id

    @router.get("/profiles")
    def list_profiles(session: Session = Depends(current_session)) -> dict[str, Any]:
        principal(session)
        return {
            "enabled": settings.enabled,
            "profiles": profile_listing(),
            "approved_templates": sorted(settings.approved_templates),
            "target_types": ["ip", "cidr"],
        }

    @router.post("/executions", status_code=202, dependencies=[Depends(require_csrf)])
    def create_execution(
        organization_id: str,
        engagement_id: str,
        payload: NucleiExecutionRequest,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        user_id = principal(session)
        if not settings.enabled:
            raise HTTPException(status_code=404, detail="Nuclei integration is disabled.")
        try:
            result = governance.create_governed_job(
                user_id,
                organization_id,
                engagement_id,
                payload.asset_id,
                technique="vulnerability_scan",
                approval_id=payload.approval_id,
                idempotency_key=payload.idempotency_key,
                chain_request={"profile": payload.profile, "templates": payload.templates},
            )
        except ValueError:
            raise HTTPException(
                status_code=409,
                detail={"code": "execution_request_conflict", "message": "The request is invalid."},
            ) from None
        if result.get("decision") == "REQUIRE_APPROVAL":
            raise HTTPException(status_code=409, detail={"code": "approval_required"})
        if result.get("decision") == "DENY":
            raise HTTPException(
                status_code=403,
                detail={"code": result.get("reason_code", "policy_denied")},
            )
        return result

    @router.get("/executions/{job_id}/result")
    def get_result(
        organization_id: str,
        engagement_id: str,
        job_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        user_id = principal(session)
        job = governance.get_job(user_id, organization_id, job_id)
        if (
            job is None
            or job["engagement_id"] != engagement_id
            or job["technique"] != "vulnerability_scan"
        ):
            raise HTTPException(status_code=404, detail="Nuclei execution not found.")
        scan_id = job.get("scan_id")
        if not scan_id:
            raise HTTPException(status_code=404, detail="Nuclei result not found.")
        with repository.member_context(organization_id, user_id, write=False):
            result = repository.get("evidence", scan_id)
        if result is None or result.get("evidence_type") != "nuclei_result":
            raise HTTPException(status_code=404, detail="Nuclei result not found.")
        return result

    return router
