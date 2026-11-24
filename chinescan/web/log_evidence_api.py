"""Tenant-scoped registration and governed dispatch for configured log evidence."""

# FastAPI's Depends calls are required endpoint declarations.
# ruff: noqa: B008

from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.accounts import Session
from chinescan.core.engagement_security import EngagementSecurityService
from chinescan.core.execution_governance import ExecutionGovernanceService
from chinescan.core.log_evidence import LogEvidenceError, LogEvidenceStore
from chinescan.web.log_jobs import LogSourceError, LogSourceRegistry


class LogEvidenceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = Field(min_length=1, max_length=80)
    label: str = Field(min_length=1, max_length=120)


class LogExecutionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(default_factory=lambda: str(uuid4()), min_length=16, max_length=80)


class LogEvidenceHold(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=500)


def create_log_evidence_router(
    store: LogEvidenceStore,
    security: EngagementSecurityService,
    registry: LogSourceRegistry,
    governance: ExecutionGovernanceService,
    current_session: Any,
    require_csrf: Any,
) -> APIRouter:
    router = APIRouter(
        prefix="/api/organizations/{organization_id}/engagements/{engagement_id}/log-evidence",
        tags=["governed-log-analysis"],
    )

    def principal(session: Session) -> str:
        if not session.user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return session.user_id

    @router.get("")
    def list_evidence(
        organization_id: str,
        engagement_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        result = store.list_for(principal(session), organization_id, engagement_id, security)
        if result is None:
            raise HTTPException(status_code=404, detail="Engagement evidence is unavailable.")
        return {"items": result}

    @router.get("/sources")
    def list_configured_sources(
        organization_id: str,
        engagement_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        allowed = store.list_for(principal(session), organization_id, engagement_id, security)
        if allowed is None:
            raise HTTPException(status_code=404, detail="Engagement evidence is unavailable.")
        return {"items": registry.entries()}

    @router.post("", status_code=201, dependencies=[Depends(require_csrf)])
    def register_evidence(
        organization_id: str,
        engagement_id: str,
        payload: LogEvidenceCreate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            _name, source, rules, iocs = registry.resolve(payload.source_id)
            if rules is not None or iocs is not None:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "governed_custom_log_configuration_unsupported",
                        "message": (
                            "Custom rules and IOC lists are not yet supported "
                            "for governed evidence."
                        ),
                    },
                )
            result = store.register(
                principal(session), organization_id, engagement_id, source, payload.label, security
            )
        except LogSourceError:
            raise HTTPException(
                status_code=404, detail="Configured log source is unavailable."
            ) from None
        except LogEvidenceError as exc:
            if (
                exc.code.startswith("evidence_source")
                or exc.code == "evidence_registration_forbidden"
            ):
                raise HTTPException(
                    status_code=404, detail="Engagement evidence is unavailable."
                ) from None
            raise HTTPException(
                status_code=422,
                detail={
                    "code": exc.code,
                    "message": "The evidence source could not be safely registered.",
                },
            ) from None
        if result is None:
            raise HTTPException(status_code=404, detail="Engagement evidence is unavailable.")
        return result

    @router.post(
        "/{asset_id}/executions", status_code=202, dependencies=[Depends(require_csrf)]
    )
    def create_execution(
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        payload: LogExecutionCreate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        if len(asset_id) != 36:
            raise HTTPException(status_code=404, detail="Engagement evidence is unavailable.")
        try:
            result = governance.create_governed_job(
                principal(session), organization_id, engagement_id, asset_id,
                technique="log_analysis", approval_id=None,
                idempotency_key=payload.idempotency_key,
            )
        except OverflowError:
            raise HTTPException(
                status_code=429,
                detail={"code": "execution_queue_full", "message": "Execution queue is full."},
            ) from None
        except ValueError:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "execution_request_conflict",
                    "message": "Execution request conflicts with an existing job.",
                },
            ) from None
        if result.get("decision") != "ALLOW":
            code = result.get("reason_code", "policy_denied")
            status = 409 if result.get("decision") == "REQUIRE_APPROVAL" else 403
            raise HTTPException(
                status_code=status,
                detail={
                    "code": code,
                    "message": result.get("explanation", "Execution was denied by policy."),
                },
            )
        return result

    @router.post("/{asset_id}/hold", status_code=204, dependencies=[Depends(require_csrf)])
    def place_evidence_hold(
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        payload: LogEvidenceHold,
        session: Session = Depends(current_session),
    ) -> Response:
        try:
            placed = store.place_hold_for_asset(
                principal(session), organization_id, engagement_id, asset_id,
                payload.reason, security,
            )
        except LogEvidenceError:
            raise HTTPException(
                status_code=422, detail="Evidence hold could not be recorded."
            ) from None
        if not placed:
            raise HTTPException(status_code=404, detail="Engagement evidence is unavailable.")
        return Response(status_code=204)

    @router.delete("/{asset_id}", status_code=204, dependencies=[Depends(require_csrf)])
    def delete_evidence(
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        session: Session = Depends(current_session),
    ) -> Response:
        try:
            deleted = store.delete_asset(
                principal(session), organization_id, engagement_id, asset_id, security
            )
        except LogEvidenceError:
            raise HTTPException(
                status_code=503, detail="Evidence deletion could not be completed."
            ) from None
        if not deleted:
            raise HTTPException(status_code=404, detail="Engagement evidence is unavailable.")
        return Response(status_code=204)

    return router
