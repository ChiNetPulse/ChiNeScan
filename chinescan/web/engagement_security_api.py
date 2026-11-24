"""Tenant- and engagement-scoped APIs for Phase 1C authorization records."""

# FastAPI dependency injection intentionally uses Depends in endpoint defaults.
# ruff: noqa: B008

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.accounts import Session
from chinescan.core.engagement_security import (
    MAX_AUTHORIZATION_DOCUMENT_BYTES,
    EngagementSecurityError,
    EngagementSecurityService,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssetCreate(StrictModel):
    asset_type: str
    target: str = Field(min_length=1, max_length=2048)
    client_id: str | None = Field(default=None, min_length=36, max_length=36)
    description: str | None = Field(default=None, max_length=2000)


class AssetUpdate(StrictModel):
    asset_type: str | None = None
    target: str | None = Field(default=None, min_length=1, max_length=2048)
    description: str | None = Field(default=None, max_length=2000)
    status: str | None = None


class ScopeRuleInput(StrictModel):
    asset_id: str = Field(min_length=36, max_length=36)
    effect: str
    match_mode: str
    techniques: list[str] = Field(default_factory=list, max_length=32)


class ScopeCreate(StrictModel):
    change_summary: str = Field(min_length=1, max_length=2000)
    rules: list[ScopeRuleInput] = Field(min_length=1, max_length=200)


class AuthorizationCreate(StrictModel):
    scope_revision_id: str = Field(min_length=36, max_length=36)
    authorization_reference: str = Field(min_length=1, max_length=160)
    authorizing_party: str = Field(min_length=1, max_length=200)
    permitted_techniques: list[str] = Field(min_length=1, max_length=32)
    effective_at: str = Field(min_length=20, max_length=40)
    expires_at: str = Field(min_length=20, max_length=40)


class ApprovalCreate(StrictModel):
    asset_type: str
    target: str = Field(min_length=1, max_length=2048)
    technique: str = Field(min_length=1, max_length=80)
    expires_at: str | None = Field(default=None, max_length=40)


class ApprovalDecision(StrictModel):
    decision: str
    reason: str = Field(default="", max_length=500)


class PolicyEvaluate(StrictModel):
    asset_type: str
    target: str = Field(min_length=1, max_length=2048)
    technique: str = Field(min_length=1, max_length=80)
    approval_id: str | None = Field(default=None, min_length=36, max_length=36)
    consume_approval: bool = False


def _principal(session: Session) -> str:
    if not session.user_id:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return session.user_id


def _missing() -> HTTPException:
    return HTTPException(status_code=404, detail="Resource not found.")


def _invalid(exc: EngagementSecurityError) -> HTTPException:
    return HTTPException(
        status_code=422, detail={"code": "invalid_engagement_security_input", "message": str(exc)}
    )


def create_engagement_security_router(
    service: EngagementSecurityService,
    current_session: Any,
    require_csrf: Any,
) -> APIRouter:
    router = APIRouter(
        prefix="/api/organizations/{organization_id}/engagements/{engagement_id}",
        tags=["engagement-security"],
    )

    @router.get("/assets")
    def list_assets(
        organization_id: str, engagement_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        items = service.list_assets(_principal(session), organization_id, engagement_id)
        if items is None:
            raise _missing()
        return {"items": items}

    @router.post("/assets", status_code=201, dependencies=[Depends(require_csrf)])
    def create_asset(
        organization_id: str,
        engagement_id: str,
        payload: AssetCreate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            item = service.create_asset(
                _principal(session),
                organization_id,
                engagement_id,
                payload.asset_type,
                payload.target,
                payload.client_id,
                payload.description,
            )
        except EngagementSecurityError as exc:
            raise _invalid(exc) from None
        if item is None:
            raise _missing()
        return item

    @router.get("/assets/{asset_id}")
    def get_asset(
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        items = service.list_assets(_principal(session), organization_id, engagement_id)
        if items is None:
            raise _missing()
        item = next((entry for entry in items if entry["id"] == asset_id), None)
        if item is None:
            raise _missing()
        return item

    @router.patch("/assets/{asset_id}", dependencies=[Depends(require_csrf)])
    def update_asset(
        organization_id: str,
        engagement_id: str,
        asset_id: str,
        payload: AssetUpdate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            item = service.update_asset(
                _principal(session),
                organization_id,
                engagement_id,
                asset_id,
                **payload.model_dump(exclude_unset=True),
            )
        except EngagementSecurityError as exc:
            raise _invalid(exc) from None
        if item is None:
            raise _missing()
        return item

    @router.get("/scope/revisions")
    def list_scope_revisions(
        organization_id: str, engagement_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        items = service.scope_revisions(_principal(session), organization_id, engagement_id)
        if items is None:
            raise _missing()
        return {"items": items}

    @router.post("/scope/revisions", status_code=201, dependencies=[Depends(require_csrf)])
    def create_scope_revision(
        organization_id: str,
        engagement_id: str,
        payload: ScopeCreate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            item = service.create_scope_revision(
                _principal(session),
                organization_id,
                engagement_id,
                [rule.model_dump() for rule in payload.rules],
                payload.change_summary,
            )
        except EngagementSecurityError as exc:
            raise _invalid(exc) from None
        if item is None:
            raise _missing()
        return item

    @router.get("/scope/revisions/{revision_id}")
    def get_scope_revision(
        organization_id: str,
        engagement_id: str,
        revision_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        item = service.get_scope_revision(
            _principal(session), organization_id, engagement_id, revision_id
        )
        if item is None:
            raise _missing()
        return item

    @router.post("/scope/revisions/{revision_id}/publish", dependencies=[Depends(require_csrf)])
    def publish_scope_revision(
        organization_id: str,
        engagement_id: str,
        revision_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            item = service.publish_scope_revision(
                _principal(session), organization_id, engagement_id, revision_id
            )
        except EngagementSecurityError as exc:
            raise _invalid(exc) from None
        if item is None:
            raise _missing()
        return item

    @router.get("/authorizations")
    def list_authorizations(
        organization_id: str, engagement_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        items = service.list_authorizations(_principal(session), organization_id, engagement_id)
        if items is None:
            raise _missing()
        return {"items": items}

    @router.post("/authorizations", status_code=201, dependencies=[Depends(require_csrf)])
    def create_authorization(
        organization_id: str,
        engagement_id: str,
        payload: AuthorizationCreate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            item = service.create_authorization(
                _principal(session),
                organization_id,
                engagement_id,
                payload.scope_revision_id,
                payload.authorization_reference,
                payload.authorizing_party,
                payload.permitted_techniques,
                payload.effective_at,
                payload.expires_at,
            )
        except EngagementSecurityError as exc:
            raise _invalid(exc) from None
        if item is None:
            raise _missing()
        return item

    @router.post("/authorizations/{authorization_id}/revoke", dependencies=[Depends(require_csrf)])
    def revoke_authorization(
        organization_id: str,
        engagement_id: str,
        authorization_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        item = service.revoke_authorization(
            _principal(session), organization_id, engagement_id, authorization_id
        )
        if item is None:
            raise _missing()
        return item

    @router.put("/authorizations/{authorization_id}/document", dependencies=[Depends(require_csrf)])
    async def put_authorization_document(
        organization_id: str,
        engagement_id: str,
        authorization_id: str,
        request: Request,
        filename: str = Query(min_length=1, max_length=180),
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            declared = request.headers.get("content-length")
            if declared is not None and int(declared) > MAX_AUTHORIZATION_DOCUMENT_BYTES:
                raise _invalid(EngagementSecurityError("Authorization document exceeds 10 MiB."))
            chunks: list[bytes] = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_AUTHORIZATION_DOCUMENT_BYTES:
                    raise _invalid(
                        EngagementSecurityError("Authorization document exceeds 10 MiB.")
                    )
                chunks.append(chunk)
            content = b"".join(chunks)
            item = service.put_authorization_document(
                _principal(session),
                organization_id,
                engagement_id,
                authorization_id,
                filename,
                request.headers.get("content-type", "application/octet-stream"),
                content,
            )
        except (EngagementSecurityError, ValueError) as exc:
            if isinstance(exc, EngagementSecurityError):
                raise _invalid(exc) from None
            raise HTTPException(status_code=400, detail="Content-Length is invalid.") from None
        if item is None:
            raise _missing()
        return item

    @router.get("/authorizations/{authorization_id}/document")
    def get_authorization_document(
        organization_id: str,
        engagement_id: str,
        authorization_id: str,
        session: Session = Depends(current_session),
    ) -> Response:
        item = service.get_authorization_document(
            _principal(session), organization_id, engagement_id, authorization_id
        )
        if item is None:
            raise _missing()
        return Response(
            content=item["content"],
            media_type=item["content_type"],
            headers={
                "Content-Disposition": f'attachment; filename="{item["filename"]}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, no-store",
                "X-Document-SHA256": item["sha256"],
            },
        )

    @router.get("/approvals")
    def list_approvals(
        organization_id: str, engagement_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        items = service.list_approvals(_principal(session), organization_id, engagement_id)
        if items is None:
            raise _missing()
        return {"items": items}

    @router.get("/approvals/{approval_id}")
    def get_approval(
        organization_id: str,
        engagement_id: str,
        approval_id: str,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        items = service.list_approvals(_principal(session), organization_id, engagement_id)
        if items is None:
            raise _missing()
        item = next((entry for entry in items if entry["id"] == approval_id), None)
        if item is None:
            raise _missing()
        return item

    @router.post("/approvals", status_code=201, dependencies=[Depends(require_csrf)])
    def create_approval(
        organization_id: str,
        engagement_id: str,
        payload: ApprovalCreate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            item = service.create_approval_request(
                _principal(session),
                organization_id,
                engagement_id,
                payload.asset_type,
                payload.target,
                payload.technique,
                payload.expires_at,
            )
        except EngagementSecurityError as exc:
            raise _invalid(exc) from None
        if item is None:
            raise _missing()
        return item

    @router.post("/approvals/{approval_id}/decision", dependencies=[Depends(require_csrf)])
    def decide_approval(
        organization_id: str,
        engagement_id: str,
        approval_id: str,
        payload: ApprovalDecision,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            item = service.decide_approval(
                _principal(session),
                organization_id,
                engagement_id,
                approval_id,
                payload.decision,
                payload.reason,
            )
        except EngagementSecurityError as exc:
            raise _invalid(exc) from None
        if item is None:
            raise _missing()
        return item

    @router.post("/policy/evaluate", dependencies=[Depends(require_csrf)])
    def evaluate_policy(
        organization_id: str,
        engagement_id: str,
        payload: PolicyEvaluate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        if payload.consume_approval:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "approval_consumption_requires_execution",
                    "message": (
                        "Policy evaluation cannot consume an approval. Consumption must be "
                        "atomic with a future authorized execution boundary."
                    ),
                },
            )
        try:
            return service.evaluate_policy(
                _principal(session),
                organization_id,
                engagement_id,
                payload.asset_type,
                payload.target,
                payload.technique,
                payload.approval_id,
            )
        except EngagementSecurityError as exc:
            raise _invalid(exc) from None

    @router.get("/audit")
    def audit_history(
        organization_id: str,
        engagement_id: str,
        limit: int = Query(default=100, ge=1, le=200),
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        items = service.audit_history(_principal(session), organization_id, engagement_id, limit)
        if items is None:
            raise _missing()
        return {"items": items}

    return router
