"""Persistent identity and tenant services for the Phase 1B foundation."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import and_, select, update

from chinescan.core.accounts import normalize_email
from chinescan.core.storage.sqlite import (
    clients,
    engagement_assignments,
    engagements,
    organization_audit_events,
    organization_bootstrap_reports,
    organization_memberships,
    organizations,
    record_ownership,
    records,
    repository_asset_bindings,
    repository_snapshots,
    users,
)

ORG_ROLES = {"owner", "admin", "member", "auditor", "viewer"}
ENGAGEMENT_ROLES = {"lead", "assessor", "reviewer", "observer"}
MEMBERSHIP_STATES = {"active", "suspended", "revoked"}
ENGAGEMENT_STATES = {"draft", "active", "paused", "completed", "archived"}


class OrganizationError(ValueError):
    """Expected organization or membership operation failure."""


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _dict(row: Any) -> dict[str, Any]:
    return dict(row._mapping) if row is not None else {}


class OrganizationService:
    def __init__(self, repository: Any) -> None:
        self.repository = repository
        self.engine = repository.engine
        self.operator_user_id: str | None = None
        self.load_platform_superuser()

    def load_platform_superuser(self) -> str | None:
        """Load the persisted platform superuser when the schema supports it."""
        try:
            with self.engine.connect() as connection:
                user_id = connection.execute(
                    select(users.c.id).where(
                        users.c.platform_role == "superuser",
                        users.c.status == "active",
                    )
                ).scalar_one_or_none()
        except Exception:
            # Older local SQLite databases predate the platform_role column;
            # their existing credential-file bootstrap remains authoritative.
            return self.operator_user_id
        self.operator_user_id = str(user_id) if user_id is not None else None
        return self.operator_user_id

    def user_id_for_email(self, email: str) -> str | None:
        normalized = normalize_email(email)
        with self.engine.connect() as connection:
            user_id = connection.execute(
                select(users.c.id).where(users.c.email_normalized == normalized)
            ).scalar_one_or_none()
            return str(user_id) if user_id is not None else None

    def personal_organization_id(self, user_id: str) -> str | None:
        slug = f"personal-{user_id.replace('-', '')[:20]}"
        with self.engine.connect() as connection:
            row = connection.execute(
                select(organizations.c.id)
                .join(
                    organization_memberships,
                    organization_memberships.c.organization_id == organizations.c.id,
                )
                .where(
                    organizations.c.slug == slug,
                    organizations.c.status == "active",
                    organization_memberships.c.user_id == user_id,
                    organization_memberships.c.role == "owner",
                    organization_memberships.c.status == "active",
                )
            ).scalar_one_or_none()
            return str(row) if row else None

    @staticmethod
    def _audit(
        connection: Any,
        organization_id: str,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        connection.execute(
            organization_audit_events.insert().values(
                id=str(uuid4()),
                organization_id=organization_id,
                actor_user_id=actor_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                created_at=now_iso(),
            )
        )

    def ensure_operator(
        self, email: str, auth_epoch: str, identity_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Idempotently link the existing credential-file operator to a personal org.

        Credential hashes, TOTP state, reset tokens and recovery data remain solely
        in the existing protected credential file.
        """
        normalized = normalize_email(email)
        timestamp = now_iso()
        with self.engine.begin() as connection:
            email_row = connection.execute(
                select(users).where(users.c.email_normalized == normalized)
            ).first()
            user_row = (
                connection.execute(select(users).where(users.c.id == identity_id)).first()
                if identity_id
                else email_row
            )
            if user_row is not None and email_row is not None and user_row.id != email_row.id:
                raise OrganizationError("Operator email is already assigned to another identity.")
            if identity_id and user_row is None and email_row is not None:
                raise OrganizationError(
                    "Operator identity reference conflicts with stored identity."
                )
            if user_row:
                user = _dict(user_row)
                if user["status"] != "active":
                    raise OrganizationError("The account is suspended or archived.")
                changes = {
                    "email_normalized": normalized,
                    "display_name": normalized,
                    "auth_epoch": auth_epoch,
                    "platform_role": "superuser",
                }
                if any(user[key] != value for key, value in changes.items()):
                    connection.execute(
                        update(users)
                        .where(users.c.id == user["id"])
                        .values(**changes, updated_at=timestamp)
                    )
                    user.update(**changes, updated_at=timestamp)
            else:
                user = {
                    "id": identity_id or str(uuid4()),
                    "email_normalized": normalized,
                    "display_name": normalized,
                    "status": "active",
                    "platform_role": "superuser",
                    "auth_epoch": auth_epoch,
                    "created_at": timestamp,
                    "updated_at": timestamp,
                }
                connection.execute(users.insert().values(**user))
            self.operator_user_id = user["id"]

            personal_slug = f"personal-{user['id'].replace('-', '')[:20]}"
            org_row = connection.execute(
                select(organizations).where(organizations.c.slug == personal_slug)
            ).first()
            if org_row:
                org = _dict(org_row)
                if org["status"] != "active":
                    raise OrganizationError("The personal organization is not active.")
            else:
                org = {
                    "id": str(uuid4()),
                    "name": "Personal workspace",
                    "slug": personal_slug,
                    "status": "active",
                    "owner_user_id": user["id"],
                    "created_at": timestamp,
                    "updated_at": timestamp,
                }
                connection.execute(organizations.insert().values(**org))

            membership = connection.execute(
                select(organization_memberships).where(
                    organization_memberships.c.organization_id == org["id"],
                    organization_memberships.c.user_id == user["id"],
                )
            ).first()
            if membership:
                membership_data = _dict(membership)
                if membership_data["status"] != "active" or membership_data["role"] != "owner":
                    connection.execute(
                        update(organization_memberships)
                        .where(organization_memberships.c.id == membership_data["id"])
                        .values(role="owner", status="active", updated_at=timestamp)
                    )
            else:
                connection.execute(
                    organization_memberships.insert().values(
                        id=str(uuid4()),
                        organization_id=org["id"],
                        user_id=user["id"],
                        role="owner",
                        status="active",
                        created_at=timestamp,
                        updated_at=timestamp,
                    )
                )

            all_records = connection.execute(
                select(records.c.record_type, records.c.record_id)
            ).all()
            existing = {
                (row.record_type, row.record_id): row.organization_id
                for row in connection.execute(
                    select(
                        record_ownership.c.record_type,
                        record_ownership.c.record_id,
                        record_ownership.c.organization_id,
                    )
                ).all()
            }
            mapped = 0
            skipped = 0
            for record in all_records:
                key = (record.record_type, record.record_id)
                if key in existing:
                    skipped += 1
                    continue
                connection.execute(
                    record_ownership.insert().values(
                        record_type=record.record_type,
                        record_id=record.record_id,
                        organization_id=org["id"],
                        engagement_id=None,
                        created_at=timestamp,
                    )
                )
                mapped += 1
            total = len(all_records)
            accessible = connection.execute(
                select(record_ownership.c.record_type, record_ownership.c.record_id).where(
                    record_ownership.c.organization_id == org["id"]
                )
            ).all()
            unresolved = total - len(set((row.record_type, row.record_id) for row in accessible))
            verified = sum(
                1
                for record in all_records
                if existing.get((record.record_type, record.record_id)) == org["id"]
                or (record.record_type, record.record_id) not in existing
            )
            invalid_references = len(
                connection.exec_driver_sql("PRAGMA foreign_key_check(record_ownership)").all()
            )
            report = {
                "report_id": "phase1b-legacy-record-ownership",
                "total_legacy_records_discovered": total,
                "records_successfully_mapped": verified,
                "records_newly_mapped_this_run": mapped,
                "records_skipped_already_mapped": skipped,
                "records_with_unresolved_ownership": unresolved,
                "duplicate_mappings": 0,
                "invalid_or_orphaned_references": invalid_references,
                "records_verified_after_migration": verified,
                "warnings": (
                    ["Some legacy records map elsewhere and remain inaccessible."]
                    if unresolved
                    else []
                )
                + (["Ownership table has invalid references."] if invalid_references else []),
                "created_at": timestamp,
            }
            previous_report = connection.execute(
                select(organization_bootstrap_reports).where(
                    organization_bootstrap_reports.c.report_id == report["report_id"]
                )
            ).first()
            previous_payload = _dict(previous_report).get("payload") if previous_report else None
            if not isinstance(previous_payload, dict) or any(
                key != "created_at" and previous_payload.get(key) != value
                for key, value in report.items()
            ):
                connection.execute(
                    organization_bootstrap_reports.delete().where(
                        organization_bootstrap_reports.c.report_id == report["report_id"]
                    )
                )
                connection.execute(
                    organization_bootstrap_reports.insert().values(
                        report_id=report["report_id"], payload=report, created_at=timestamp
                    )
                )
            self.repository._local_operator_organization_id = org["id"]
            return user, org

    def get_active_user(self, user_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(users).where(users.c.id == user_id, users.c.status == "active")
            ).first()
            return _dict(row) or None

    def membership_context(self, user_id: str, requested_organization_id: str | None) -> str | None:
        organization_id = requested_organization_id or self.personal_organization_id(user_id)
        if not organization_id or not self.has_role(user_id, organization_id, ORG_ROLES):
            return None
        return organization_id

    def current_user(self, user_id: str) -> dict[str, Any]:
        with self.engine.connect() as connection:
            row = connection.execute(select(users).where(users.c.id == user_id)).first()
            return _dict(row)

    def accessible_organizations(self, user_id: str) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(
                    organizations,
                    organization_memberships.c.role.label("role"),
                    organization_memberships.c.id.label("membership_id"),
                )
                .join(
                    organization_memberships,
                    organization_memberships.c.organization_id == organizations.c.id,
                )
                .where(
                    organization_memberships.c.user_id == user_id,
                    organization_memberships.c.status == "active",
                    organizations.c.status == "active",
                )
                .order_by(organizations.c.name, organizations.c.id)
            ).all()
            return [dict(row._mapping) for row in rows]

    def has_role(self, user_id: str, organization_id: str, roles: set[str]) -> bool:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(organization_memberships.c.role)
                .join(
                    organizations, organizations.c.id == organization_memberships.c.organization_id
                )
                .join(users, users.c.id == organization_memberships.c.user_id)
                .where(
                    organization_memberships.c.user_id == user_id,
                    organization_memberships.c.organization_id == organization_id,
                    organization_memberships.c.status == "active",
                    organizations.c.status == "active",
                    users.c.status == "active",
                )
            ).first()
            return bool(row and row.role in roles)

    def membership_role(self, user_id: str, organization_id: str) -> str | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(organization_memberships.c.role)
                .join(
                    organizations, organizations.c.id == organization_memberships.c.organization_id
                )
                .join(users, users.c.id == organization_memberships.c.user_id)
                .where(
                    organization_memberships.c.user_id == user_id,
                    organization_memberships.c.organization_id == organization_id,
                    organization_memberships.c.status == "active",
                    organizations.c.status == "active",
                    users.c.status == "active",
                )
            ).first()
            return row.role if row else None

    def organization(self, organization_id: str, user_id: str) -> dict[str, Any] | None:
        if not self.has_role(user_id, organization_id, ORG_ROLES):
            return None
        with self.engine.connect() as connection:
            return _dict(
                connection.execute(
                    select(organizations).where(organizations.c.id == organization_id)
                ).first()
            )

    def members(self, organization_id: str, user_id: str) -> list[dict[str, Any]]:
        if not self.has_role(user_id, organization_id, ORG_ROLES):
            return []
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(organization_memberships, users.c.email_normalized, users.c.display_name)
                .join(users, users.c.id == organization_memberships.c.user_id)
                .where(organization_memberships.c.organization_id == organization_id)
                .order_by(users.c.email_normalized)
            ).all()
            return [dict(row._mapping) for row in rows]

    def create_organization(self, user_id: str, name: str, slug: str) -> dict[str, Any]:
        timestamp = now_iso()
        normalized_slug = re.sub(r"[^a-z0-9-]+", "-", slug.strip().lower()).strip("-")
        if not normalized_slug or len(normalized_slug) > 100:
            raise OrganizationError("Organization slug is invalid.")
        org_id = str(uuid4())
        with self.engine.begin() as connection:
            if not connection.execute(
                select(users.c.id).where(users.c.id == user_id, users.c.status == "active")
            ).first():
                raise OrganizationError("Active user required.")
            org = {
                "id": org_id,
                "name": name.strip(),
                "slug": normalized_slug,
                "status": "active",
                "owner_user_id": user_id,
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            connection.execute(organizations.insert().values(**org))
            connection.execute(
                organization_memberships.insert().values(
                    id=str(uuid4()),
                    organization_id=org_id,
                    user_id=user_id,
                    role="owner",
                    status="active",
                    created_at=timestamp,
                    updated_at=timestamp,
                )
            )
            self._audit(connection, org_id, user_id, "organization.created", "organization", org_id)
        return org

    def update_organization(
        self, user_id: str, organization_id: str, **changes: Any
    ) -> dict[str, Any] | None:
        if not self.has_role(user_id, organization_id, {"owner", "admin"}):
            return None
        changes["updated_at"] = now_iso()
        with self.engine.begin() as connection:
            connection.execute(
                update(organizations).where(organizations.c.id == organization_id).values(**changes)
            )
            self._audit(
                connection,
                organization_id,
                user_id,
                "organization.updated",
                "organization",
                organization_id,
            )
            return _dict(
                connection.execute(
                    select(organizations).where(organizations.c.id == organization_id)
                ).first()
            )

    def update_membership(
        self,
        actor_id: str,
        organization_id: str,
        user_id: str,
        *,
        role: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any] | None:
        actor_role = self.membership_role(actor_id, organization_id)
        if actor_role not in {"owner", "admin"}:
            return None
        if role is not None and role not in ORG_ROLES:
            raise OrganizationError("Membership role is invalid.")
        if status is not None and status not in MEMBERSHIP_STATES:
            raise OrganizationError("Membership status is invalid.")
        with self.engine.begin() as connection:
            target = connection.execute(
                select(organization_memberships).where(
                    organization_memberships.c.organization_id == organization_id,
                    organization_memberships.c.user_id == user_id,
                )
            ).first()
            if target is None:
                return None
            target_data = _dict(target)
            next_role = role or target_data["role"]
            next_status = status or target_data["status"]
            if actor_role != "owner" and (
                target_data["role"] == "owner" or next_role in {"owner", "admin"}
            ):
                raise OrganizationError(
                    "Only an organization owner can change owner or admin roles."
                )
            if target_data["role"] == "owner" and (next_role != "owner" or next_status != "active"):
                other_owner = connection.execute(
                    select(organization_memberships.c.id)
                    .where(
                        organization_memberships.c.organization_id == organization_id,
                        organization_memberships.c.role == "owner",
                        organization_memberships.c.status == "active",
                        organization_memberships.c.user_id != user_id,
                    )
                    .limit(1)
                ).first()
                if other_owner is None:
                    raise OrganizationError("The last active owner cannot be removed or demoted.")
            values = {"updated_at": now_iso()}
            if role is not None:
                values["role"] = role
            if status is not None:
                values["status"] = status
            connection.execute(
                update(organization_memberships)
                .where(organization_memberships.c.id == target_data["id"])
                .values(**values)
            )
            self._audit(
                connection,
                organization_id,
                actor_id,
                "membership.updated",
                "membership",
                target_data["id"],
            )
            return _dict(
                connection.execute(
                    select(organization_memberships).where(
                        organization_memberships.c.id == target_data["id"]
                    )
                ).first()
            )

    def add_member(
        self, actor_id: str, organization_id: str, target_user_id: str, role: str = "member"
    ) -> dict[str, Any] | None:
        if role not in ORG_ROLES or role == "owner":
            raise OrganizationError("Membership role is invalid.")
        actor_role = self.membership_role(actor_id, organization_id)
        if actor_role not in {"owner", "admin"}:
            return None
        if actor_role != "owner" and role == "admin":
            raise OrganizationError("Only an organization owner can grant the admin role.")
        timestamp = now_iso()
        with self.engine.begin() as connection:
            target = connection.execute(
                select(users.c.id).where(users.c.id == target_user_id, users.c.status == "active")
            ).first()
            if not target:
                raise OrganizationError("An existing active user is required.")
            existing = connection.execute(
                select(organization_memberships).where(
                    organization_memberships.c.organization_id == organization_id,
                    organization_memberships.c.user_id == target_user_id,
                )
            ).first()
            if existing:
                item = _dict(existing)
                if item["status"] == "active":
                    raise OrganizationError("Membership already exists.")
                connection.execute(
                    update(organization_memberships)
                    .where(organization_memberships.c.id == item["id"])
                    .values(role=role, status="active", updated_at=timestamp)
                )
                self._audit(
                    connection,
                    organization_id,
                    actor_id,
                    "membership.reactivated",
                    "membership",
                    item["id"],
                )
                return {**item, "role": role, "status": "active", "updated_at": timestamp}
            item = {
                "id": str(uuid4()),
                "organization_id": organization_id,
                "user_id": target_user_id,
                "role": role,
                "status": "active",
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            connection.execute(organization_memberships.insert().values(**item))
            self._audit(
                connection,
                organization_id,
                actor_id,
                "membership.created",
                "membership",
                item["id"],
            )
            return item

    def clients(self, user_id: str, organization_id: str) -> list[dict[str, Any]]:
        if not self.has_role(user_id, organization_id, ORG_ROLES):
            return []
        with self.engine.connect() as connection:
            return [
                _dict(row)
                for row in connection.execute(
                    select(clients)
                    .where(clients.c.organization_id == organization_id)
                    .order_by(clients.c.name)
                ).all()
            ]

    def client(self, user_id: str, organization_id: str, client_id: str) -> dict[str, Any] | None:
        if not self.has_role(user_id, organization_id, ORG_ROLES):
            return None
        with self.engine.connect() as connection:
            return (
                _dict(
                    connection.execute(
                        select(clients).where(
                            clients.c.id == client_id, clients.c.organization_id == organization_id
                        )
                    ).first()
                )
                or None
            )

    def update_client(
        self, user_id: str, organization_id: str, client_id: str, **changes: Any
    ) -> dict[str, Any] | None:
        if not self.has_role(user_id, organization_id, {"owner", "admin", "member"}):
            return None
        changes["updated_at"] = now_iso()
        with self.engine.begin() as connection:
            result = connection.execute(
                update(clients)
                .where(clients.c.id == client_id, clients.c.organization_id == organization_id)
                .values(**changes)
            )
            if result.rowcount != 1:
                return None
            self._audit(connection, organization_id, user_id, "client.updated", "client", client_id)
            return _dict(
                connection.execute(
                    select(clients).where(
                        clients.c.id == client_id, clients.c.organization_id == organization_id
                    )
                ).first()
            )

    def create_client(
        self, user_id: str, organization_id: str, name: str, description: str | None
    ) -> dict[str, Any] | None:
        if not self.has_role(user_id, organization_id, {"owner", "admin", "member"}):
            return None
        timestamp, item_id = now_iso(), str(uuid4())
        row = {
            "id": item_id,
            "organization_id": organization_id,
            "name": name.strip(),
            "description": description,
            "status": "active",
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        with self.engine.begin() as connection:
            connection.execute(clients.insert().values(**row))
            self._audit(connection, organization_id, user_id, "client.created", "client", item_id)
        return row

    def engagements(self, user_id: str, organization_id: str) -> list[dict[str, Any]]:
        if not self.has_role(user_id, organization_id, ORG_ROLES):
            return []
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(engagements)
                .where(engagements.c.organization_id == organization_id)
                .order_by(engagements.c.updated_at.desc())
            ).all()
            return [
                _dict(row)
                for row in rows
                if self._can_read_engagement(connection, user_id, organization_id, row.id)
            ]

    @staticmethod
    def _can_read_engagement(
        connection: Any, user_id: str, organization_id: str, engagement_id: str
    ) -> bool:
        role = connection.execute(
            select(organization_memberships.c.role)
            .join(organizations, organizations.c.id == organization_memberships.c.organization_id)
            .join(users, users.c.id == organization_memberships.c.user_id)
            .where(
                organization_memberships.c.organization_id == organization_id,
                organization_memberships.c.user_id == user_id,
                organization_memberships.c.status == "active",
                organizations.c.status == "active",
                users.c.status == "active",
            )
        ).scalar_one_or_none()
        if role in {"owner", "admin", "auditor", "viewer"}:
            return True
        return bool(
            connection.execute(
                select(engagement_assignments.c.id)
                .join(
                    organization_memberships,
                    and_(
                        organization_memberships.c.organization_id
                        == engagement_assignments.c.organization_id,
                        organization_memberships.c.user_id == engagement_assignments.c.user_id,
                    ),
                )
                .join(organizations, organizations.c.id == engagement_assignments.c.organization_id)
                .join(engagements, engagements.c.id == engagement_assignments.c.engagement_id)
                .join(users, users.c.id == engagement_assignments.c.user_id)
                .where(
                    engagement_assignments.c.organization_id == organization_id,
                    engagement_assignments.c.engagement_id == engagement_id,
                    engagement_assignments.c.user_id == user_id,
                    engagement_assignments.c.status == "active",
                    organization_memberships.c.status == "active",
                    organizations.c.status == "active",
                    engagements.c.status == "active",
                    users.c.status == "active",
                )
                .limit(1)
            ).first()
        )

    def engagement(
        self, user_id: str, organization_id: str, engagement_id: str
    ) -> dict[str, Any] | None:
        if not self.has_role(user_id, organization_id, ORG_ROLES):
            return None
        with self.engine.connect() as connection:
            row = connection.execute(
                select(engagements).where(
                    engagements.c.id == engagement_id,
                    engagements.c.organization_id == organization_id,
                )
            ).first()
            if row is None or not self._can_read_engagement(
                connection, user_id, organization_id, engagement_id
            ):
                return None
            return _dict(row)

    def update_engagement(
        self, user_id: str, organization_id: str, engagement_id: str, **changes: Any
    ) -> dict[str, Any] | None:
        if not self.has_role(
            user_id, organization_id, {"owner", "admin"}
        ) and not self._has_assignment(user_id, organization_id, engagement_id, {"lead"}):
            return None
        if "status" in changes and changes["status"] not in ENGAGEMENT_STATES:
            raise OrganizationError("Engagement status is invalid.")
        with self.engine.begin() as connection:
            client_id = changes.get("client_id")
            if (
                client_id
                and not connection.execute(
                    select(clients.c.id).where(
                        clients.c.id == client_id, clients.c.organization_id == organization_id
                    )
                ).first()
            ):
                raise OrganizationError("Client must belong to the same organization.")
            changes["updated_at"] = now_iso()
            if "status" in changes:
                current = connection.execute(
                    select(engagements.c.status, engagements.c.closed_at).where(
                        engagements.c.id == engagement_id,
                        engagements.c.organization_id == organization_id,
                    )
                ).first()
                if current is None:
                    return None
                if changes["status"] in {"completed", "archived"} and current.status not in {
                    "completed",
                    "archived",
                }:
                    closure_time = now_iso()
                    changes["closed_at"] = closure_time
                elif changes["status"] not in {"completed", "archived"}:
                    changes["closed_at"] = None
            result = connection.execute(
                update(engagements)
                .where(
                    engagements.c.id == engagement_id,
                    engagements.c.organization_id == organization_id,
                )
                .values(**changes)
            )
            if result.rowcount != 1:
                return None
            if "status" in changes:
                bound = (
                    connection.execute(
                        select(repository_asset_bindings.c.snapshot_id)
                        .where(
                            repository_asset_bindings.c.organization_id == organization_id,
                            repository_asset_bindings.c.engagement_id == engagement_id,
                        )
                        .distinct()
                    )
                    .scalars()
                    .all()
                )
                for snapshot_id in bound:
                    links = connection.execute(
                        select(
                            repository_asset_bindings.c.engagement_id,
                        ).where(
                            repository_asset_bindings.c.snapshot_id == snapshot_id,
                            repository_asset_bindings.c.organization_id == organization_id,
                        )
                    ).all()
                    closures = []
                    open_link = False
                    for link in links:
                        linked_engagement = connection.execute(
                            select(engagements.c.status, engagements.c.closed_at).where(
                                engagements.c.id == link.engagement_id,
                                engagements.c.organization_id == organization_id,
                            )
                        ).first()
                        if (
                            not linked_engagement
                            or linked_engagement.status not in {"completed", "archived"}
                            or not linked_engagement.closed_at
                        ):
                            open_link = True
                            break
                        closures.append(
                            datetime.fromisoformat(
                                linked_engagement.closed_at.replace("Z", "+00:00")
                            )
                        )
                    if open_link or not closures:
                        connection.execute(
                            update(repository_snapshots)
                            .where(
                                repository_snapshots.c.id == snapshot_id,
                                repository_snapshots.c.organization_id == organization_id,
                            )
                            .values(closed_at=None, delete_after=None)
                        )
                        retention_action = "repository.snapshot_retention_released"
                    else:
                        latest_closure = max(closures)
                        delete_after = (latest_closure + timedelta(days=90)).isoformat()
                        connection.execute(
                            update(repository_snapshots)
                            .where(
                                repository_snapshots.c.id == snapshot_id,
                                repository_snapshots.c.organization_id == organization_id,
                            )
                            .values(closed_at=latest_closure.isoformat(), delete_after=delete_after)
                        )
                        retention_action = "repository.snapshot_retention_scheduled"
                    self._audit(
                        connection,
                        organization_id,
                        user_id,
                        retention_action,
                        "repository_snapshot",
                        str(snapshot_id),
                    )
            self._audit(
                connection,
                organization_id,
                user_id,
                "engagement.closed" if changes.get("closed_at") else "engagement.updated",
                "engagement",
                engagement_id,
            )
            return _dict(
                connection.execute(
                    select(engagements).where(
                        engagements.c.id == engagement_id,
                        engagements.c.organization_id == organization_id,
                    )
                ).first()
            )

    def create_engagement(
        self,
        user_id: str,
        organization_id: str,
        client_id: str | None,
        name: str,
        description: str,
        status: str = "draft",
    ) -> dict[str, Any] | None:
        if not self.has_role(user_id, organization_id, {"owner", "admin", "member"}):
            return None
        if status not in ENGAGEMENT_STATES:
            raise OrganizationError("Engagement status is invalid.")
        timestamp, item_id = now_iso(), str(uuid4())
        row = {
            "id": item_id,
            "organization_id": organization_id,
            "client_id": client_id,
            "name": name.strip(),
            "description": description,
            "status": status,
            "closed_at": timestamp if status in {"completed", "archived"} else None,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        with self.engine.begin() as connection:
            if (
                client_id
                and not connection.execute(
                    select(clients.c.id).where(
                        clients.c.id == client_id, clients.c.organization_id == organization_id
                    )
                ).first()
            ):
                raise OrganizationError("Client must belong to the same organization.")
            connection.execute(engagements.insert().values(**row))
            connection.execute(
                engagement_assignments.insert().values(
                    id=str(uuid4()),
                    organization_id=organization_id,
                    engagement_id=item_id,
                    user_id=user_id,
                    role="lead",
                    status="active",
                    created_at=timestamp,
                    updated_at=timestamp,
                )
            )
            self._audit(
                connection, organization_id, user_id, "engagement.created", "engagement", item_id
            )
        return row

    def assignments(
        self, actor_id: str, organization_id: str, engagement_id: str
    ) -> list[dict[str, Any]] | None:
        if not self.has_role(
            actor_id, organization_id, {"owner", "admin"}
        ) and not self._has_assignment(
            actor_id, organization_id, engagement_id, {"lead", "reviewer"}
        ):
            return None
        with self.engine.connect() as connection:
            if not connection.execute(
                select(engagements.c.id).where(
                    engagements.c.id == engagement_id,
                    engagements.c.organization_id == organization_id,
                )
            ).first():
                return None
            rows = connection.execute(
                select(engagement_assignments, users.c.email_normalized, users.c.display_name)
                .join(users, users.c.id == engagement_assignments.c.user_id)
                .where(
                    engagement_assignments.c.organization_id == organization_id,
                    engagement_assignments.c.engagement_id == engagement_id,
                )
            ).all()
            return [dict(row._mapping) for row in rows]

    def change_assignment(
        self,
        actor_id: str,
        organization_id: str,
        engagement_id: str,
        target_user_id: str,
        *,
        role: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any] | None:
        if not self.has_role(
            actor_id, organization_id, {"owner", "admin"}
        ) and not self._has_assignment(actor_id, organization_id, engagement_id, {"lead"}):
            return None
        if role is not None and role not in ENGAGEMENT_ROLES:
            raise OrganizationError("Engagement role is invalid.")
        if status is not None and status not in {"active", "revoked"}:
            raise OrganizationError("Assignment status is invalid.")
        timestamp = now_iso()
        with self.engine.begin() as connection:
            if not connection.execute(
                select(engagements.c.id).where(
                    engagements.c.id == engagement_id,
                    engagements.c.organization_id == organization_id,
                )
            ).first():
                return None
            if not connection.execute(
                select(organization_memberships.c.id)
                .join(users, users.c.id == organization_memberships.c.user_id)
                .join(
                    organizations,
                    organizations.c.id == organization_memberships.c.organization_id,
                )
                .where(
                    organization_memberships.c.organization_id == organization_id,
                    organization_memberships.c.user_id == target_user_id,
                    organization_memberships.c.status == "active",
                    organizations.c.status == "active",
                    users.c.status == "active",
                )
            ).first():
                raise OrganizationError("Assignee must be an active organization member.")
            old = connection.execute(
                select(engagement_assignments).where(
                    engagement_assignments.c.engagement_id == engagement_id,
                    engagement_assignments.c.user_id == target_user_id,
                )
            ).first()
            if old:
                item = _dict(old)
                next_status = status if status is not None else item["status"]
                values = {"status": next_status, "updated_at": timestamp}
                if role is not None:
                    values["role"] = role
                connection.execute(
                    update(engagement_assignments)
                    .where(engagement_assignments.c.id == item["id"])
                    .values(**values)
                )
                self._audit(
                    connection,
                    organization_id,
                    actor_id,
                    "assignment.reactivated"
                    if item["status"] == "revoked" and next_status == "active"
                    else "assignment.revoked"
                    if next_status == "revoked" and item["status"] != "revoked"
                    else "assignment.updated",
                    "assignment",
                    item["id"],
                )
                return {**item, **values}
            if role is None:
                raise OrganizationError("Assignment role is required.")
            item = {
                "id": str(uuid4()),
                "organization_id": organization_id,
                "engagement_id": engagement_id,
                "user_id": target_user_id,
                "role": role,
                "status": status or "active",
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            connection.execute(engagement_assignments.insert().values(**item))
            self._audit(
                connection,
                organization_id,
                actor_id,
                "assignment.created",
                "assignment",
                item["id"],
            )
            return item

    def _has_assignment(
        self, user_id: str, organization_id: str, engagement_id: str, roles: set[str]
    ) -> bool:
        with self.engine.connect() as connection:
            return bool(
                connection.execute(
                    select(engagement_assignments.c.id)
                    .join(
                        organization_memberships,
                        and_(
                            organization_memberships.c.organization_id
                            == engagement_assignments.c.organization_id,
                            organization_memberships.c.user_id == engagement_assignments.c.user_id,
                        ),
                    )
                    .join(
                        organizations,
                        organizations.c.id == engagement_assignments.c.organization_id,
                    )
                    .join(engagements, engagements.c.id == engagement_assignments.c.engagement_id)
                    .join(users, users.c.id == engagement_assignments.c.user_id)
                    .where(
                        engagement_assignments.c.organization_id == organization_id,
                        engagement_assignments.c.engagement_id == engagement_id,
                        engagement_assignments.c.user_id == user_id,
                        engagement_assignments.c.role.in_(roles),
                        engagement_assignments.c.status == "active",
                        organization_memberships.c.status == "active",
                        organization_memberships.c.role == "member",
                        organizations.c.status == "active",
                        engagements.c.status == "active",
                        users.c.status == "active",
                    )
                    .limit(1)
                ).first()
            )

    def migration_report(self) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(organization_bootstrap_reports.c.payload).where(
                    organization_bootstrap_reports.c.report_id == "phase1b-legacy-record-ownership"
                )
            ).first()
            if not row:
                return None
            payload = dict(row.payload)
            payload["summary"] = (
                f"Mapped {payload['records_successfully_mapped']} of "
                f"{payload['total_legacy_records_discovered']} legacy records; "
                f"{payload['records_with_unresolved_ownership']} unresolved."
            )
            return payload
