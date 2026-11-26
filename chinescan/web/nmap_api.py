"""Authenticated API for the constrained, governed Nmap integration."""

# FastAPI dependency injection intentionally uses Depends in endpoint defaults.
# ruff: noqa: B008

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.accounts import Session
from chinescan.core.config.settings import NmapIntegrationSettings
from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.integrations.nmap.profiles import profile_listing


class NmapExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=36, max_length=36)
    profile: str = Field(min_length=1, max_length=64)
    ports: list[int] = Field(default_factory=list, max_length=64)
    approval_id: str | None = Field(default=None, min_length=36, max_length=36)
    idempotency_key: str = Field(min_length=16, max_length=80)


def create_nmap_router(
    governance: ExecutionGovernanceService,
    worker: GovernedDomainWorker,
    repository: SQLiteRepository,
    settings: NmapIntegrationSettings,
    current_session: Any,
    require_csrf: Any,
) -> APIRouter:
    del worker  # The shared governed worker owns dispatch; this router only submits jobs.
    router = APIRouter(
        prefix="/api/organizations/{organization_id}/engagements/{engagement_id}/nmap",
        tags=["governed-nmap"],
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
            "target_types": ["ip", "cidr"],
            "hostname_targets_supported": False,
        }

    @router.post("/executions", status_code=202, dependencies=[Depends(require_csrf)])
    def create_execution(
        organization_id: str,
        engagement_id: str,
        payload: NmapExecutionRequest,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        user_id = principal(session)
        if not settings.enabled:
            raise HTTPException(status_code=404, detail="Nmap integration is disabled.")
        try:
            result = governance.create_governed_job(
                user_id,
                organization_id,
                engagement_id,
                payload.asset_id,
                technique="port_scan",
                approval_id=payload.approval_id,
                idempotency_key=payload.idempotency_key,
                chain_request={"profile": payload.profile, "ports": payload.ports},
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail={"code": "execution_request_conflict", "message": str(exc)},
            ) from None
        if result.get("decision") == "REQUIRE_APPROVAL":
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "approval_required",
                    "message": "Create and obtain approval for this exact operation, then retry.",
                },
            )
        if result.get("decision") == "DENY":
            raise HTTPException(
                status_code=403,
                detail={
                    "code": result.get("reason_code", "policy_denied"),
                    "message": result.get("explanation", "Execution was denied by policy."),
                },
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
        if job is None or job["engagement_id"] != engagement_id or job["technique"] != "port_scan":
            raise HTTPException(status_code=404, detail="Nmap execution not found.")
        scan_id = job.get("scan_id")
        if not scan_id:
            raise HTTPException(status_code=404, detail="Nmap result not found.")
        with repository.member_context(organization_id, user_id, write=False):
            result = repository.get("evidence", scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Nmap result not found.")
        if result.get("evidence_type") != "nmap_result":
            raise HTTPException(status_code=404, detail="Nmap result not found.")
        return result

    return router
