"""Phase 1B organization APIs, mounted separately from legacy app routes."""

# FastAPI's Depends calls are the framework's required dependency declaration.
# ruff: noqa: B008

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from chinescan.core.accounts import Session
from chinescan.core.identity import IdentityError, IdentityService
from chinescan.core.organizations import OrganizationError, OrganizationService


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OrganizationCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9-]+$")


class OrganizationUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    status: str | None = None


class MemberCreate(StrictModel):
    user_id: str = Field(min_length=36, max_length=36)
    role: str = "member"


class MemberUpdate(StrictModel):
    role: str | None = None
    status: str | None = None


class ClientCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)


class ClientUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    status: str | None = None


class EngagementCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)
    client_id: str | None = Field(default=None, min_length=36, max_length=36)
    status: str = "draft"


class EngagementUpdate(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    client_id: str | None = Field(default=None, min_length=36, max_length=36)
    status: str | None = None


class AssignmentCreate(StrictModel):
    user_id: str = Field(min_length=36, max_length=36)
    role: str


class AssignmentUpdate(StrictModel):
    role: str | None = None
    status: str | None = None


class InvitationCreate(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    role: str = "member"
    ttl_hours: int = Field(default=168, ge=1, le=720)


def _principal(session: Session) -> str:
    if not session.user_id:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return session.user_id


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail="Resource not found.")


def _translate(exc: OrganizationError) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


def create_organization_router(
    service: OrganizationService,
    current_session: Any,
    require_csrf: Any,
    identity: IdentityService | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api", tags=["organizations"])

    @router.get("/auth/me")
    def me(session: Session = Depends(current_session)) -> dict[str, Any]:
        user = service.current_user(_principal(session))
        if not user or user.get("status") != "active":
            raise HTTPException(status_code=403, detail="Account unavailable.")
        return {
            key: user[key]
            for key in ("id", "email_normalized", "display_name", "status", "created_at")
        }

    @router.get("/organizations")
    def list_organizations(session: Session = Depends(current_session)) -> dict[str, Any]:
        return {"items": service.accessible_organizations(_principal(session))}

    @router.post("/organizations", status_code=201, dependencies=[Depends(require_csrf)])
    def create_organization(
        payload: OrganizationCreate, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        try:
            return service.create_organization(_principal(session), payload.name, payload.slug)
        except Exception as exc:
            if "UNIQUE constraint" in str(exc):
                raise HTTPException(
                    status_code=409, detail="Organization slug already exists."
                ) from None
            raise

    @router.get("/organizations/{organization_id}")
    def get_organization(
        organization_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        org = service.organization(organization_id, _principal(session))
        if not org:
            raise _not_found()
        return org

    @router.patch("/organizations/{organization_id}", dependencies=[Depends(require_csrf)])
    def patch_organization(
        organization_id: str,
        payload: OrganizationUpdate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        changes = payload.model_dump(exclude_unset=True)
        if not changes or any(value is None for value in changes.values()):
            raise HTTPException(status_code=422, detail="At least one valid field is required.")
        if "status" in changes and changes["status"] not in {"active", "suspended", "archived"}:
            raise HTTPException(status_code=422, detail="Organization status is invalid.")
        result = service.update_organization(_principal(session), organization_id, **changes)
        if not result:
            raise _not_found()
        return result

    @router.get("/organizations/{organization_id}/members")
    def list_members(
        organization_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        if not service.organization(organization_id, _principal(session)):
            raise _not_found()
        return {"items": service.members(organization_id, _principal(session))}

    @router.post(
        "/organizations/{organization_id}/members",
        status_code=201,
        dependencies=[Depends(require_csrf)],
    )
    def add_member(
        organization_id: str, payload: MemberCreate, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        try:
            member = service.add_member(
                _principal(session), organization_id, payload.user_id, payload.role
            )
        except OrganizationError as exc:
            raise _translate(exc) from None
        if not member:
            raise _not_found()
        return member

    @router.get("/organizations/{organization_id}/members/{user_id}")
    def get_member(
        organization_id: str, user_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        if not service.organization(organization_id, _principal(session)):
            raise _not_found()
        member = next(
            (
                item
                for item in service.members(organization_id, _principal(session))
                if item["user_id"] == user_id
            ),
            None,
        )
        if not member:
            raise _not_found()
        return member

    @router.patch(
        "/organizations/{organization_id}/members/{user_id}", dependencies=[Depends(require_csrf)]
    )
    def patch_member(
        organization_id: str,
        user_id: str,
        payload: MemberUpdate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            member = service.update_membership(
                _principal(session),
                organization_id,
                user_id,
                **payload.model_dump(exclude_unset=True),
            )
        except OrganizationError as exc:
            raise _translate(exc) from None
        if not member:
            raise _not_found()
        return member

    @router.get("/organizations/{organization_id}/clients")
    def list_clients(
        organization_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        if not service.organization(organization_id, _principal(session)):
            raise _not_found()
        return {"items": service.clients(_principal(session), organization_id)}

    @router.post(
        "/organizations/{organization_id}/clients",
        status_code=201,
        dependencies=[Depends(require_csrf)],
    )
    def create_client(
        organization_id: str, payload: ClientCreate, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        result = service.create_client(
            _principal(session), organization_id, payload.name, payload.description
        )
        if not result:
            raise _not_found()
        return result

    @router.get("/organizations/{organization_id}/clients/{client_id}")
    def get_client(
        organization_id: str, client_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        result = service.client(_principal(session), organization_id, client_id)
        if not result:
            raise _not_found()
        return result

    @router.patch(
        "/organizations/{organization_id}/clients/{client_id}", dependencies=[Depends(require_csrf)]
    )
    def patch_client(
        organization_id: str,
        client_id: str,
        payload: ClientUpdate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        changes = payload.model_dump(exclude_unset=True)
        if not changes:
            raise HTTPException(status_code=422, detail="At least one field is required.")
        if "status" in changes and changes["status"] not in {"active", "archived"}:
            raise HTTPException(status_code=422, detail="Client status is invalid.")
        result = service.update_client(_principal(session), organization_id, client_id, **changes)
        if not result:
            raise _not_found()
        return result

    @router.get("/organizations/{organization_id}/engagements")
    def list_engagements(
        organization_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        if not service.organization(organization_id, _principal(session)):
            raise _not_found()
        return {"items": service.engagements(_principal(session), organization_id)}

    @router.post(
        "/organizations/{organization_id}/engagements",
        status_code=201,
        dependencies=[Depends(require_csrf)],
    )
    def create_engagement(
        organization_id: str, payload: EngagementCreate, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        try:
            result = service.create_engagement(
                _principal(session),
                organization_id,
                payload.client_id,
                payload.name,
                payload.description,
                payload.status,
            )
        except OrganizationError as exc:
            raise _translate(exc) from None
        if not result:
            raise _not_found()
        return result

    @router.get("/organizations/{organization_id}/engagements/{engagement_id}")
    def get_engagement(
        organization_id: str, engagement_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        result = service.engagement(_principal(session), organization_id, engagement_id)
        if not result:
            raise _not_found()
        return result

    @router.patch(
        "/organizations/{organization_id}/engagements/{engagement_id}",
        dependencies=[Depends(require_csrf)],
    )
    def patch_engagement(
        organization_id: str,
        engagement_id: str,
        payload: EngagementUpdate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        changes = payload.model_dump(exclude_unset=True)
        if not changes:
            raise HTTPException(status_code=422, detail="At least one field is required.")
        try:
            result = service.update_engagement(
                _principal(session), organization_id, engagement_id, **changes
            )
        except OrganizationError as exc:
            raise _translate(exc) from None
        if not result:
            raise _not_found()
        return result

    @router.get("/organizations/{organization_id}/engagements/{engagement_id}/assignments")
    def list_assignments(
        organization_id: str, engagement_id: str, session: Session = Depends(current_session)
    ) -> dict[str, Any]:
        result = service.assignments(_principal(session), organization_id, engagement_id)
        if result is None:
            raise _not_found()
        return {"items": result}

    @router.post(
        "/organizations/{organization_id}/engagements/{engagement_id}/assignments",
        status_code=201,
        dependencies=[Depends(require_csrf)],
    )
    def create_assignment(
        organization_id: str,
        engagement_id: str,
        payload: AssignmentCreate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            result = service.change_assignment(
                _principal(session),
                organization_id,
                engagement_id,
                payload.user_id,
                role=payload.role,
            )
        except OrganizationError as exc:
            raise _translate(exc) from None
        if not result:
            raise _not_found()
        return result

    @router.patch(
        "/organizations/{organization_id}/engagements/{engagement_id}/assignments/{user_id}",
        dependencies=[Depends(require_csrf)],
    )
    def patch_assignment(
        organization_id: str,
        engagement_id: str,
        user_id: str,
        payload: AssignmentUpdate,
        session: Session = Depends(current_session),
    ) -> dict[str, Any]:
        changes = payload.model_dump(exclude_unset=True)
        if not changes:
            raise HTTPException(status_code=422, detail="At least one field is required.")
        try:
            result = service.change_assignment(
                _principal(session),
                organization_id,
                engagement_id,
                user_id,
                role=changes.get("role"),
                status=changes.get("status"),
            )
        except OrganizationError as exc:
            raise _translate(exc) from None
        if not result:
            raise _not_found()
        return result

    @router.get("/organization-migration-report")
    def migration_report(session: Session = Depends(current_session)) -> dict[str, Any]:
        user_id = _principal(session)
        if not service.operator_user_id or user_id != service.operator_user_id:
            raise _not_found()
        return service.migration_report() or {"status": "not_available"}

    if identity is not None:

        @router.get("/organizations/{organization_id}/invitations")
        def list_invitations(
            organization_id: str, session: Session = Depends(current_session)
        ) -> dict[str, Any]:
            items = identity.list_invitations(_principal(session), organization_id)
            if items is None:
                raise _not_found()
            return {"items": items}

        @router.post(
            "/organizations/{organization_id}/invitations",
            status_code=201,
            dependencies=[Depends(require_csrf)],
        )
        def create_invitation(
            organization_id: str,
            payload: InvitationCreate,
            session: Session = Depends(current_session),
        ) -> dict[str, Any]:
            try:
                item = identity.create_invitation(
                    _principal(session),
                    organization_id,
                    payload.email,
                    payload.role,
                    ttl_hours=payload.ttl_hours,
                )
            except IdentityError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from None
            if item is None:
                raise _not_found()
            return item

        @router.post(
            "/organizations/{organization_id}/invitations/{invitation_id}/revoke",
            dependencies=[Depends(require_csrf)],
        )
        def revoke_invitation(
            organization_id: str,
            invitation_id: str,
            session: Session = Depends(current_session),
        ) -> dict[str, str]:
            if not identity.revoke_invitation(_principal(session), organization_id, invitation_id):
                raise _not_found()
            return {"status": "revoked"}

    return router
