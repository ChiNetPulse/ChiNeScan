"""Authenticated API for policy-governed domain assessment jobs."""

# FastAPI dependency injection intentionally uses Depends in endpoint defaults.
# ruff: noqa: B008

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.accounts import Session
from chinescan.core.execution_governance import ExecutionGovernanceService, GovernedDomainWorker
from chinescan.core.resource_governance import ResourceLimitError


class DomainExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=36, max_length=36)
    approval_id: str | None = Field(default=None, min_length=36, max_length=36)
    idempotency_key: str = Field(min_length=16, max_length=80)


class ChainImportExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=36, max_length=36)
    chain: str = Field(min_length=1, max_length=32)
    seed: str = Field(min_length=1, max_length=128)
    depth: int = Field(ge=1, le=6)
    idempotency_key: str = Field(min_length=16, max_length=80)


class ChainProviderExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=36, max_length=36)
    approval_id: str = Field(min_length=36, max_length=36)
    idempotency_key: str = Field(min_length=16, max_length=80)


def create_execution_router(
    governance: ExecutionGovernanceService,
    worker: GovernedDomainWorker,
    current_session: Any,
    require_csrf: Any,
) -> APIRouter:
    router = APIRouter(
        prefix="/api/organizations/{organization_id}/engagements/{engagement_id}/executions",
        tags=["governed-execution"],
    )

    def principal(session: Session) -> str:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session.user_id

    @router.post("/domain", status_code=202, dependencies=[Depends(require_csrf)])
    def create_domain_execution(
        organization_id: str,
        engagement_id: str,
        payload: DomainExecutionRequest,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            result = governance.create_domain_job(
                principal(session),
                organization_id,
                engagement_id,
                payload.asset_id,
                approval_id=payload.approval_id,
                idempotency_key=payload.idempotency_key,
            )
        except ResourceLimitError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"code": exc.code, "message": exc.message, "details": exc.details},
            ) from None
        except OverflowError:
            raise HTTPException(
                status_code=429,
                detail={"code": "execution_queue_full", "message": "Execution queue is full."},
            ) from None
        except ValueError as exc:
            raise HTTPException(
                status_code=409, detail={"code": "execution_request_conflict", "message": str(exc)}
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

    @router.get("/quota")
    def get_execution_quota(
        organization_id: str,
        engagement_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        del engagement_id
        try:
            return governance.get_organization_resource_usage(principal(session), organization_id)
        except PermissionError:
            raise HTTPException(status_code=404, detail="Organization not found.") from None

    @router.get("/{job_id}")
    def get_execution(
        organization_id: str,
        engagement_id: str,
        job_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        item = governance.get_job(principal(session), organization_id, job_id)
        if item is None or item["engagement_id"] != engagement_id:
            raise HTTPException(status_code=404, detail="Execution job not found.")
        return item

    @router.get("/{job_id}/provenance")
    def get_execution_provenance(
        organization_id: str,
        engagement_id: str,
        job_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        result = governance.get_job_provenance(
            principal(session), organization_id, engagement_id, job_id
        )
        if result is None:
            raise HTTPException(status_code=404, detail="Execution provenance not found.")
        return result

    @router.post("/{job_id}/cancel", status_code=202, dependencies=[Depends(require_csrf)])
    def cancel_execution(
        organization_id: str,
        engagement_id: str,
        job_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        result = worker.request_cancellation(
            principal(session), organization_id, engagement_id, job_id
        )
        if result is None:
            raise HTTPException(status_code=404, detail="Execution job not found.")
        if result["outcome"] == "forbidden":
            # Keep job existence hidden from a member without cancellation permission.
            raise HTTPException(status_code=404, detail="Execution job not found.")
        if result["outcome"] == "terminal":
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "execution_job_terminal",
                    "message": "Cancellation is unavailable because the job is already terminal.",
                },
            )
        job = result["job"]
        return {
            **job,
            "cancellation_outcome": result["outcome"],
            "idempotent": result.get("idempotent", False),
        }

    @router.get("")
    def list_executions(
        organization_id: str,
        engagement_id: str,
        limit: int = Query(default=50, ge=1, le=100),
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        items = governance.list_jobs(principal(session), organization_id, engagement_id, limit)
        if items is None:
            raise HTTPException(status_code=404, detail="Engagement not found.")
        return {"items": items}

    return router


def create_chain_execution_router(
    governance: ExecutionGovernanceService,
    worker: GovernedDomainWorker,
    current_session: Any,
    require_csrf: Any,
) -> APIRouter:
    """Expose separate policy-governed local-import and approved provider operations."""
    del worker  # Durable jobs are dispatched by the established worker lifecycle.
    router = APIRouter(
        prefix="/api/organizations/{organization_id}/engagements/{engagement_id}/chain-traces",
        tags=["governed-chain-trace"],
    )

    @router.post("/imports", status_code=202, dependencies=[Depends(require_csrf)])
    def create_import(
        organization_id: str,
        engagement_id: str,
        payload: ChainImportExecutionRequest,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        try:
            result = governance.create_governed_job(
                session.user_id,
                organization_id,
                engagement_id,
                payload.asset_id,
                technique="chain_trace_import",
                approval_id=None,
                idempotency_key=payload.idempotency_key,
                chain_request={
                    "chain": payload.chain,
                    "seed": payload.seed,
                    "depth": payload.depth,
                },
            )
        except (ValueError, OverflowError):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "chain_admission_denied",
                    "message": "Chain import could not be admitted.",
                },
            ) from None
        if result.get("decision") != "ALLOW":
            raise HTTPException(
                status_code=403,
                detail={
                    "code": result.get("reason_code", "policy_denied"),
                    "message": result.get("explanation", "Execution was denied by policy."),
                },
            )
        return result

    @router.post("/provider-lookups", status_code=202, dependencies=[Depends(require_csrf)])
    def create_provider_lookup(
        organization_id: str,
        engagement_id: str,
        payload: ChainProviderExecutionRequest,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        try:
            result = governance.create_governed_job(
                session.user_id,
                organization_id,
                engagement_id,
                payload.asset_id,
                technique="chain_provider_lookup",
                approval_id=payload.approval_id,
                idempotency_key=payload.idempotency_key,
            )
        except (ValueError, OverflowError):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "chain_admission_denied",
                    "message": "Provider lookup could not be admitted.",
                },
            ) from None
        if result.get("decision") == "REQUIRE_APPROVAL":
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "approval_required",
                    "message": "A valid approval for this exact provider lookup is required.",
                },
            )
        if result.get("decision") != "ALLOW":
            raise HTTPException(
                status_code=403,
                detail={
                    "code": result.get("reason_code", "policy_denied"),
                    "message": result.get("explanation", "Execution was denied by policy."),
                },
            )
        return result

    return router
