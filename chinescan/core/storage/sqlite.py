"""SQLAlchemy-backed SQLite repository."""

import hmac
import json
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, cast, overload
from uuid import uuid4

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import (
    DDL,
    JSON,
    CheckConstraint,
    Column,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    case,
    create_engine,
    event,
    func,
    inspect,
    or_,
    select,
)
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.engine.reflection import Inspector

from chinescan.core.errors import StorageError
from chinescan.core.storage.repository import Repository


def begin_immediate(connection: Connection) -> None:
    """Acquire a SQLite write lock immediately, or start a transaction on other dialects."""
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN IMMEDIATE")
    elif not connection.in_transaction():
        connection.begin()


metadata = MetaData()
records = Table(
    "records",
    metadata,
    Column("record_type", String(80), primary_key=True),
    Column("record_id", String(255), primary_key=True),
    Column("payload", JSON, nullable=False),
)

# Phase 1B identity and engagement foundation. Keep legacy records in the
# existing JSON table and scope them through record_ownership.
users = Table(
    "users",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("email_normalized", String(254), nullable=False, unique=True, index=True),
    Column("display_name", String(120), nullable=False),
    Column("status", String(20), nullable=False),
    Column("platform_role", String(20), nullable=False, default="user", server_default="user"),
    Column("auth_epoch", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint("platform_role IN ('user', 'superuser')", name="ck_users_platform_role"),
)
organizations = Table(
    "organizations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(160), nullable=False),
    Column("slug", String(100), nullable=False, unique=True, index=True),
    Column("status", String(20), nullable=False),
    Column("owner_user_id", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="RESTRICT"),
)
organization_memberships = Table(
    "organization_memberships",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("user_id", String(36), nullable=False, index=True),
    Column("role", String(20), nullable=False),
    Column("status", String(20), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
    UniqueConstraint("organization_id", "user_id", name="uq_membership_org_user"),
)
clients = Table(
    "clients",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("name", String(160), nullable=False),
    Column("description", String(2000)),
    Column("status", String(20), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    UniqueConstraint("id", "organization_id", name="uq_client_id_org"),
)
engagements = Table(
    "engagements",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("client_id", String(36)),
    Column("name", String(160), nullable=False),
    Column("description", String(4000), nullable=False),
    Column("status", String(20), nullable=False),
    Column("closed_at", String(40)),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(
        ["client_id", "organization_id"],
        ["clients.id", "clients.organization_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint("id", "organization_id", name="uq_engagement_id_org"),
)
engagement_assignments = Table(
    "engagement_assignments",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("engagement_id", String(36), nullable=False, index=True),
    Column("user_id", String(36), nullable=False, index=True),
    Column("role", String(20), nullable=False),
    Column("status", String(20), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["organization_id", "user_id"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint("engagement_id", "user_id", name="uq_assignment_engagement_user"),
)
record_ownership = Table(
    "record_ownership",
    metadata,
    Column("record_type", String(80), primary_key=True),
    Column("record_id", String(255), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("engagement_id", String(36)),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["record_type", "record_id"],
        ["records.record_type", "records.record_id"],
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="RESTRICT",
    ),
)
organization_bootstrap_reports = Table(
    "organization_bootstrap_reports",
    metadata,
    Column("report_id", String(80), primary_key=True),
    Column("payload", JSON, nullable=False),
    Column("created_at", String(40), nullable=False),
)
organization_audit_events = Table(
    "organization_audit_events",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("actor_user_id", String(36), nullable=False),
    Column("action", String(80), nullable=False),
    Column("resource_type", String(40), nullable=False),
    Column("resource_id", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="RESTRICT"),
)

# Phase 1C engagement assets, immutable scope revisions, authorization,
# one-use approvals, and append-only policy decision evidence.
engagement_assets = Table(
    "engagement_assets",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False, index=True),
    Column("client_id", String(36)),
    Column("engagement_id", String(36)),
    Column("asset_type", String(20), nullable=False),
    Column("target", String(2048), nullable=False),
    Column("description", String(2000)),
    Column("status", String(20), nullable=False),
    Column("created_by", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(
        ["client_id", "organization_id"],
        ["clients.id", "clients.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "created_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint("id", "organization_id", name="uq_engagement_asset_id_org"),
    UniqueConstraint(
        "id", "organization_id", "engagement_id", name="uq_engagement_asset_id_org_engagement"
    ),
    UniqueConstraint(
        "organization_id",
        "engagement_id",
        "asset_type",
        "target",
        name="uq_engagement_asset_target",
    ),
    CheckConstraint(
        "asset_type IN ("
        "'domain','ip','cidr','url','repository','log_evidence','malware_evidence','chain_address'"
        ")",
        name="ck_asset_type",
    ),
    CheckConstraint("status IN ('active','inactive')", name="ck_asset_status"),
)
Index(
    "ix_assets_engagement",
    engagement_assets.c.organization_id,
    engagement_assets.c.engagement_id,
)

repository_snapshots = Table(
    "repository_snapshots",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("manifest", JSON, nullable=False),
    Column("manifest_version", Integer, nullable=False),
    Column("scanner_version", String(80), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("status", String(20), nullable=False),
    Column("closed_at", String(40)),
    Column("delete_after", String(40)),
    Column("legal_hold", Integer, nullable=False, server_default="0"),
    Column("hold_reason", String(500)),
    Column("deleted_at", String(40)),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
    UniqueConstraint("id", "organization_id", name="uq_repository_snapshot_id_org"),
    CheckConstraint("size_bytes BETWEEN 0 AND 10737418240", name="ck_repository_snapshot_size"),
    CheckConstraint("manifest_version > 0", name="ck_repository_manifest_version"),
    CheckConstraint(
        "status IN ('available','missing','corrupt','deleting','deleted')",
        name="ck_repository_snapshot_status",
    ),
    CheckConstraint("legal_hold IN (0,1)", name="ck_repository_snapshot_hold"),
)
Index(
    "ix_repository_snapshot_org_status",
    repository_snapshots.c.organization_id,
    repository_snapshots.c.status,
)

repository_asset_bindings = Table(
    "repository_asset_bindings",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("asset_id", String(36), nullable=False),
    Column("project_registry_id", String(80), nullable=False),
    Column("source_kind", String(40), nullable=False),
    Column("snapshot_id", String(36), nullable=False),
    Column("snapshot_sha256", String(64), nullable=False),
    Column("created_by", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("display_label", String(120), nullable=False),
    ForeignKeyConstraint(
        ["asset_id", "organization_id", "engagement_id"],
        [
            "engagement_assets.id",
            "engagement_assets.organization_id",
            "engagement_assets.engagement_id",
        ],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "organization_id"],
        ["repository_snapshots.id", "repository_snapshots.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "created_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint("asset_id", name="uq_repository_binding_asset"),
    UniqueConstraint(
        "id", "organization_id", "engagement_id", "asset_id", name="uq_repository_binding_scope"
    ),
    CheckConstraint("source_kind = 'local_project_registry'", name="ck_repository_source_kind"),
)
Index(
    "ix_repository_binding_tenant",
    repository_asset_bindings.c.organization_id,
    repository_asset_bindings.c.engagement_id,
)

repository_attestations = Table(
    "repository_attestations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("asset_id", String(36), nullable=False),
    Column("authorization_id", String(36), nullable=False),
    Column("scope_revision_id", String(36), nullable=False),
    Column("actor_user_id", String(36), nullable=False),
    Column("attestation_version", String(40), nullable=False),
    Column("attestation_text", String(1000), nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["asset_id", "organization_id", "engagement_id"],
        [
            "engagement_assets.id",
            "engagement_assets.organization_id",
            "engagement_assets.engagement_id",
        ],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["authorization_id", "organization_id"],
        ["authorization_records.id", "authorization_records.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["scope_revision_id", "organization_id"],
        ["scope_revisions.id", "scope_revisions.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "actor_user_id"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint(
        "id",
        "organization_id",
        "engagement_id",
        "asset_id",
        "authorization_id",
        "scope_revision_id",
        name="uq_repository_attestation_binding",
    ),
    UniqueConstraint("id", "organization_id", name="uq_repository_attestation_id_org"),
)
Index(
    "ix_repository_attestation_asset",
    repository_attestations.c.organization_id,
    repository_attestations.c.engagement_id,
    repository_attestations.c.asset_id,
)

repository_quota_reservations = Table(
    "repository_quota_reservations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("reserved_bytes", Integer, nullable=False),
    Column("content_digest", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    CheckConstraint("reserved_bytes >= 0", name="ck_repository_reservation_bytes"),
)
Index("ix_repository_reservation_org", repository_quota_reservations.c.organization_id)

log_evidence_snapshots = Table(
    "log_evidence_snapshots",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("asset_id", String(36), nullable=False),
    Column("registered_by", String(36), nullable=False),
    Column("source_format", String(24), nullable=False),
    Column("label", String(120), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("file_count", Integer, nullable=False),
    Column("manifest", JSON, nullable=False),
    Column("manifest_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("status", String(20), nullable=False),
    Column("legal_hold", Integer, nullable=False, server_default="0"),
    Column("hold_reason", String(500)),
    Column("deleted_at", String(40)),
    ForeignKeyConstraint(
        ["asset_id", "organization_id", "engagement_id"],
        [
            "engagement_assets.id",
            "engagement_assets.organization_id",
            "engagement_assets.engagement_id",
        ],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "registered_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint(
        "id", "organization_id", "engagement_id", "asset_id", name="uq_log_snapshot_scope"
    ),
    UniqueConstraint("asset_id", name="uq_log_snapshot_asset"),
    CheckConstraint("size_bytes BETWEEN 0 AND 250000000", name="ck_log_snapshot_size"),
    CheckConstraint("file_count BETWEEN 1 AND 10000", name="ck_log_snapshot_file_count"),
    CheckConstraint("manifest_version = 1", name="ck_log_manifest_version"),
    CheckConstraint(
        "status IN ('available','missing','corrupt','deleted')", name="ck_log_snapshot_status"
    ),
    CheckConstraint("legal_hold IN (0,1)", name="ck_log_snapshot_hold"),
)
Index(
    "ix_log_snapshot_tenant",
    log_evidence_snapshots.c.organization_id,
    log_evidence_snapshots.c.engagement_id,
)

log_evidence_quota_reservations = Table(
    "log_evidence_quota_reservations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("reserved_bytes", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    CheckConstraint("reserved_bytes BETWEEN 0 AND 250000000", name="ck_log_reservation_bytes"),
)
Index("ix_log_reservation_org", log_evidence_quota_reservations.c.organization_id)

malware_evidence_snapshots = Table(
    "malware_evidence_snapshots",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("asset_id", String(36), nullable=False),
    Column("registered_by", String(36), nullable=False),
    Column("source_registry_id", String(80), nullable=False),
    Column("original_filename", String(255), nullable=False),
    Column("classification", String(40), nullable=False),
    Column("object_key", String(64), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("file_type", String(120), nullable=False, server_default="unknown"),
    Column("manifest", JSON, nullable=False),
    Column("manifest_sha256", String(64), nullable=False),
    Column("manifest_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("status", String(20), nullable=False),
    Column("legal_hold", Integer, nullable=False, server_default="0"),
    Column("hold_reason", String(500)),
    Column("deleted_at", String(40)),
    ForeignKeyConstraint(
        ["asset_id", "organization_id", "engagement_id"],
        [
            "engagement_assets.id",
            "engagement_assets.organization_id",
            "engagement_assets.engagement_id",
        ],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "registered_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint(
        "id", "organization_id", "engagement_id", "asset_id", name="uq_malware_snapshot_scope"
    ),
    UniqueConstraint("asset_id", name="uq_malware_snapshot_asset"),
    UniqueConstraint("object_key", name="uq_malware_snapshot_object"),
    CheckConstraint("size_bytes BETWEEN 1 AND 67108864", name="ck_malware_snapshot_size"),
    CheckConstraint("manifest_version = 1", name="ck_malware_manifest_version"),
    CheckConstraint(
        "status IN ('available','missing','corrupt','deleted')", name="ck_malware_snapshot_status"
    ),
    CheckConstraint("legal_hold IN (0,1)", name="ck_malware_snapshot_hold"),
)
Index(
    "ix_malware_snapshot_tenant",
    malware_evidence_snapshots.c.organization_id,
    malware_evidence_snapshots.c.engagement_id,
)

malware_evidence_quota_reservations = Table(
    "malware_evidence_quota_reservations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("reserved_bytes", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    CheckConstraint("reserved_bytes BETWEEN 1 AND 67108864", name="ck_malware_reservation_bytes"),
)
Index("ix_malware_reservation_org", malware_evidence_quota_reservations.c.organization_id)

event.listen(
    malware_evidence_snapshots,
    "after_create",
    DDL(
        "CREATE TRIGGER malware_evidence_snapshot_metadata_immutable "
        "BEFORE UPDATE ON malware_evidence_snapshots "
        "WHEN NEW.sha256 != OLD.sha256 OR NEW.size_bytes != OLD.size_bytes "
        "OR NEW.manifest != OLD.manifest OR NEW.manifest_sha256 != OLD.manifest_sha256 "
        "OR NEW.manifest_version != OLD.manifest_version OR NEW.object_key != OLD.object_key "
        "OR NEW.created_at != OLD.created_at OR NEW.asset_id != OLD.asset_id "
        "OR NEW.organization_id != OLD.organization_id OR NEW.engagement_id != OLD.engagement_id "
        "OR NEW.registered_by != OLD.registered_by "
        "OR NEW.original_filename != OLD.original_filename "
        "OR NEW.source_registry_id != OLD.source_registry_id "
        "OR NEW.classification != OLD.classification "
        "OR NEW.file_type != OLD.file_type "
        "BEGIN SELECT RAISE(ABORT, 'malware evidence provenance is immutable'); END"
    ).execute_if(dialect="sqlite"),  # type: ignore[no-untyped-call]
)
event.listen(
    malware_evidence_snapshots,
    "after_create",
    DDL(
        "CREATE TRIGGER malware_evidence_snapshot_no_delete "
        "BEFORE DELETE ON malware_evidence_snapshots "
        "BEGIN SELECT RAISE(ABORT, 'malware evidence snapshots are retained records'); END"
    ).execute_if(dialect="sqlite"),  # type: ignore[no-untyped-call]
)

event.listen(
    log_evidence_snapshots,
    "after_create",
    DDL(
        "CREATE TRIGGER log_evidence_snapshot_metadata_immutable "
        "BEFORE UPDATE ON log_evidence_snapshots "
        "WHEN NEW.sha256 != OLD.sha256 OR NEW.size_bytes != OLD.size_bytes "
        "OR NEW.file_count != OLD.file_count OR NEW.manifest != OLD.manifest "
        "OR NEW.manifest_version != OLD.manifest_version OR NEW.created_at != OLD.created_at "
        "OR NEW.asset_id != OLD.asset_id OR NEW.organization_id != OLD.organization_id "
        "OR NEW.engagement_id != OLD.engagement_id OR NEW.registered_by != OLD.registered_by "
        "BEGIN SELECT RAISE(ABORT, 'log evidence snapshot provenance is immutable'); END"
    ).execute_if(dialect="sqlite"),  # type: ignore[no-untyped-call]
)

for _table, _operation in (
    (repository_asset_bindings, "UPDATE"),
    (repository_asset_bindings, "DELETE"),
    (repository_attestations, "UPDATE"),
    (repository_attestations, "DELETE"),
):
    event.listen(
        _table,
        "after_create",
        DDL(
            f"CREATE TRIGGER {_table.name}_no_{_operation.lower()} "
            f"BEFORE {_operation} ON {_table.name} "
            "BEGIN SELECT RAISE(ABORT, 'repository binding and attestation records "
            "are append-only'); END"
        ).execute_if(dialect="sqlite"),  # type: ignore[no-untyped-call]
    )
event.listen(
    repository_snapshots,
    "after_create",
    DDL(
        "CREATE TRIGGER repository_snapshot_metadata_immutable "
        "BEFORE UPDATE ON repository_snapshots "
        "WHEN NEW.sha256 != OLD.sha256 OR NEW.size_bytes != OLD.size_bytes "
        "OR NEW.manifest != OLD.manifest OR NEW.manifest_version != OLD.manifest_version "
        "OR NEW.scanner_version != OLD.scanner_version OR NEW.created_at != OLD.created_at "
        "BEGIN SELECT RAISE(ABORT, 'repository snapshot metadata is immutable'); END"
    ).execute_if(dialect="sqlite"),  # type: ignore[no-untyped-call]
)

scope_revisions = Table(
    "scope_revisions",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("status", String(20), nullable=False),
    Column("created_by", String(36), nullable=False),
    Column("approved_by", String(36)),
    Column("created_at", String(40), nullable=False),
    Column("published_at", String(40)),
    Column("change_summary", String(2000), nullable=False),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["organization_id", "created_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "approved_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint("engagement_id", "revision", name="uq_scope_revision_number"),
    UniqueConstraint("id", "organization_id", name="uq_scope_revision_id_org"),
    CheckConstraint("revision > 0", name="ck_scope_revision_positive"),
    CheckConstraint("status IN ('draft','published')", name="ck_scope_revision_status"),
)
Index(
    "ix_scope_revisions_engagement",
    scope_revisions.c.organization_id,
    scope_revisions.c.engagement_id,
    scope_revisions.c.revision,
)

scope_rules = Table(
    "scope_rules",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("scope_revision_id", String(36), nullable=False),
    Column("asset_id", String(36), nullable=False),
    Column("asset_type_snapshot", String(20), nullable=False),
    Column("target_snapshot", String(2048), nullable=False),
    Column("effect", String(10), nullable=False),
    Column("match_mode", String(20), nullable=False),
    Column("techniques", JSON, nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["scope_revision_id", "organization_id"],
        ["scope_revisions.id", "scope_revisions.organization_id"],
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["asset_id", "organization_id"],
        ["engagement_assets.id", "engagement_assets.organization_id"],
        ondelete="RESTRICT",
    ),
    CheckConstraint("effect IN ('include','exclude')", name="ck_scope_rule_effect"),
    CheckConstraint(
        "match_mode IN ('exact','subdomains','network','url_prefix')",
        name="ck_scope_rule_match_mode",
    ),
)
Index("ix_scope_rules_revision", scope_rules.c.organization_id, scope_rules.c.scope_revision_id)

authorization_records = Table(
    "authorization_records",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("client_id", String(36)),
    Column("scope_revision_id", String(36), nullable=False),
    Column("authorization_reference", String(160), nullable=False),
    Column("authorizing_party", String(200), nullable=False),
    Column("permitted_techniques", JSON, nullable=False),
    Column("effective_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("status", String(20), nullable=False),
    Column("recorded_by", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["client_id", "organization_id"],
        ["clients.id", "clients.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["scope_revision_id", "organization_id"],
        ["scope_revisions.id", "scope_revisions.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "recorded_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint("id", "organization_id", name="uq_authorization_id_org"),
    UniqueConstraint("engagement_id", "authorization_reference", name="uq_authorization_reference"),
    CheckConstraint("status IN ('active','revoked')", name="ck_authorization_status"),
)
Index(
    "ix_authorizations_engagement",
    authorization_records.c.organization_id,
    authorization_records.c.engagement_id,
)

authorization_documents = Table(
    "authorization_documents",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("authorization_id", String(36), nullable=False),
    Column("filename", String(180), nullable=False),
    Column("content_type", String(120), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("content", LargeBinary, nullable=False),
    Column("created_by", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["authorization_id", "organization_id"],
        ["authorization_records.id", "authorization_records.organization_id"],
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["organization_id", "created_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint("authorization_id", name="uq_authorization_document_record"),
    CheckConstraint("size_bytes BETWEEN 1 AND 10485760", name="ck_authorization_document_size"),
)

approval_requests = Table(
    "approval_requests",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("requester_user_id", String(36), nullable=False),
    Column("approver_user_id", String(36)),
    Column("asset_type", String(20), nullable=False),
    Column("target", String(2048), nullable=False),
    Column("technique", String(80), nullable=False),
    Column("action_class", String(24), nullable=False),
    Column("scope_revision_id", String(36), nullable=False),
    Column("authorization_id", String(36), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("decision", String(20), nullable=False),
    Column("decision_reason", String(500)),
    Column("consumed_at", String(40)),
    Column("consumed_by", String(36)),
    Column("created_at", String(40), nullable=False),
    Column("decided_at", String(40)),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="CASCADE",
    ),
    UniqueConstraint("id", "organization_id", name="uq_approval_id_org"),
    ForeignKeyConstraint(
        ["organization_id", "requester_user_id"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "approver_user_id"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["organization_id", "consumed_by"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["scope_revision_id", "organization_id"],
        ["scope_revisions.id", "scope_revisions.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["authorization_id", "organization_id"],
        ["authorization_records.id", "authorization_records.organization_id"],
        ondelete="RESTRICT",
    ),
    CheckConstraint(
        "approver_user_id IS NULL OR approver_user_id != requester_user_id",
        name="ck_approval_distinct_approver",
    ),
    CheckConstraint(
        "decision IN ('pending','approved','denied','consumed','expired')",
        name="ck_approval_decision",
    ),
    CheckConstraint(
        "action_class IN ('passive','controlled_active','sensitive')",
        name="ck_approval_action_class",
    ),
)
Index(
    "ix_approval_requests_engagement",
    approval_requests.c.organization_id,
    approval_requests.c.engagement_id,
    approval_requests.c.created_at,
)
Index("ix_approval_requests_pending", approval_requests.c.decision, approval_requests.c.expires_at)

assessment_audit_events = Table(
    "assessment_audit_events",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36)),
    Column("actor_user_id", String(36), nullable=False),
    Column("action", String(80), nullable=False),
    Column("resource_type", String(40), nullable=False),
    Column("resource_id", String(36)),
    Column("decision", String(24)),
    Column("reason_code", String(80)),
    Column("details", JSON, nullable=False),
    Column("occurred_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["organization_id", "actor_user_id"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
)
Index(
    "ix_assessment_audit_org_time",
    assessment_audit_events.c.organization_id,
    assessment_audit_events.c.occurred_at,
)

execution_jobs = Table(
    "execution_jobs",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("requester_user_id", String(36), nullable=False),
    Column("asset_id", String(36), nullable=False),
    Column("target", String(2048), nullable=False),
    Column("asset_type", String(20), nullable=False),
    Column("technique", String(80), nullable=False),
    Column("action_class", String(24), nullable=False),
    Column("scope_revision_id", String(36), nullable=False),
    Column("authorization_id", String(36), nullable=False),
    Column("authorization_document_sha256", String(64)),
    Column("policy_request_digest", String(64)),
    Column("repository_binding_id", String(36)),
    Column("repository_snapshot_id", String(36)),
    Column("repository_snapshot_sha256", String(64)),
    Column("repository_manifest_version", Integer),
    Column("repository_attestation_id", String(36)),
    Column("repository_scanner_version", String(80)),
    Column("repository_scan_bounds", JSON),
    Column("repository_attestation_version", String(40)),
    Column("log_evidence_snapshot_id", String(36)),
    Column("log_evidence_sha256", String(64)),
    Column("log_evidence_manifest_version", Integer),
    Column("log_evidence_source_format", String(24)),
    Column("log_analysis_version", String(80)),
    Column("log_ruleset_version", String(80)),
    Column("malware_evidence_snapshot_id", String(36)),
    Column("malware_evidence_sha256", String(64)),
    Column("malware_evidence_manifest_sha256", String(64)),
    Column("malware_evidence_manifest_version", Integer),
    Column("malware_analysis_version", String(80)),
    Column("adapter_id", String(80)),
    Column("adapter_version", String(80)),
    Column("exclusion_policy_version", String(80)),
    Column("approval_id", String(36)),
    Column("policy_decision_id", String(36), nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("execution_context", JSON, nullable=False),
    Column("idempotency_key", String(80), nullable=False),
    Column("status", String(24), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("started_at", String(40)),
    Column("finished_at", String(40)),
    Column("scan_id", String(36)),
    Column("result_summary", JSON),
    Column("approval_consumed_at", String(40)),
    Column("cancellation_requested_at", String(40)),
    Column("cancellation_requested_by", String(36)),
    Column("cancellation_observed_at", String(40)),
    Column("error_code", String(80)),
    Column("worker_id", String(64)),
    Column("lease_generation", Integer, nullable=False, server_default="0"),
    Column("lease_expires_at", Float),
    Column("heartbeat_at", Float),
    Column("claimed_at", String(40)),
    Column("attempt_number", Integer, nullable=False, server_default="0"),
    Column("last_recovery_at", String(40)),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="CASCADE",
    ),
    ForeignKeyConstraint(
        ["organization_id", "requester_user_id"],
        ["organization_memberships.organization_id", "organization_memberships.user_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["asset_id", "organization_id", "engagement_id"],
        [
            "engagement_assets.id",
            "engagement_assets.organization_id",
            "engagement_assets.engagement_id",
        ],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["scope_revision_id", "organization_id"],
        ["scope_revisions.id", "scope_revisions.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["authorization_id", "organization_id"],
        ["authorization_records.id", "authorization_records.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["approval_id", "organization_id"],
        ["approval_requests.id", "approval_requests.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["repository_binding_id", "organization_id", "engagement_id", "asset_id"],
        [
            "repository_asset_bindings.id",
            "repository_asset_bindings.organization_id",
            "repository_asset_bindings.engagement_id",
            "repository_asset_bindings.asset_id",
        ],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["repository_snapshot_id", "organization_id"],
        ["repository_snapshots.id", "repository_snapshots.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["repository_attestation_id", "organization_id"],
        ["repository_attestations.id", "repository_attestations.organization_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["log_evidence_snapshot_id", "organization_id", "engagement_id", "asset_id"],
        [
            "log_evidence_snapshots.id",
            "log_evidence_snapshots.organization_id",
            "log_evidence_snapshots.engagement_id",
            "log_evidence_snapshots.asset_id",
        ],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(
        ["malware_evidence_snapshot_id", "organization_id", "engagement_id", "asset_id"],
        [
            "malware_evidence_snapshots.id",
            "malware_evidence_snapshots.organization_id",
            "malware_evidence_snapshots.engagement_id",
            "malware_evidence_snapshots.asset_id",
        ],
        ondelete="RESTRICT",
    ),
    UniqueConstraint(
        "organization_id",
        "engagement_id",
        "requester_user_id",
        "idempotency_key",
        name="uq_execution_job_idempotency",
    ),
    CheckConstraint(
        "status IN ("
        "'queued','claimed','running','completed','blocked','cancelled','failed',"
        "'reconciliation_required'"
        ")",
        name="ck_execution_job_status",
    ),
    CheckConstraint(
        "action_class IN ('passive','controlled_active','sensitive')",
        name="ck_execution_job_action_class",
    ),
)
Index(
    "ix_execution_jobs_org_status_created",
    execution_jobs.c.organization_id,
    execution_jobs.c.status,
    execution_jobs.c.created_at,
)
Index("ix_execution_jobs_queue", execution_jobs.c.status, execution_jobs.c.created_at)
Index(
    "ix_execution_jobs_lease_expiry",
    execution_jobs.c.status,
    execution_jobs.c.lease_expires_at,
)
Index(
    "uq_execution_job_approval_binding",
    execution_jobs.c.approval_id,
    unique=True,
    sqlite_where=execution_jobs.c.approval_id.is_not(None),
)
event.listen(
    execution_jobs,
    "after_create",
    DDL(
        "CREATE TRIGGER execution_job_auth_document_immutable "
        "BEFORE UPDATE ON execution_jobs "
        "WHEN COALESCE(NEW.authorization_document_sha256, '') "
        "!= COALESCE(OLD.authorization_document_sha256, '') "
        "BEGIN SELECT RAISE(ABORT, 'execution authorization digest is immutable'); END"
    ).execute_if(dialect="sqlite"),  # type: ignore[no-untyped-call]
)

execution_result_provenance = Table(
    "execution_result_provenance",
    metadata,
    Column("record_type", String(80), primary_key=True),
    Column("record_id", String(255), primary_key=True),
    Column("job_id", String(36), nullable=False),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "record_type IN ('scan','finding','evidence','artifact','report','malware_analysis')",
        name="ck_execution_result_provenance_type",
    ),
    ForeignKeyConstraint(
        ["record_type", "record_id"],
        ["records.record_type", "records.record_id"],
        ondelete="RESTRICT",
    ),
    ForeignKeyConstraint(["job_id"], ["execution_jobs.id"], ondelete="RESTRICT"),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="RESTRICT",
    ),
)
Index(
    "ix_execution_result_provenance_job",
    execution_result_provenance.c.job_id,
    execution_result_provenance.c.organization_id,
    execution_result_provenance.c.engagement_id,
)

# Phase 2C multi-user identity, persistent sessions, lockouts, and invitations.
user_credentials = Table(
    "user_credentials",
    metadata,
    Column("user_id", String(36), primary_key=True),
    Column("password_hash", String(255)),
    Column("totp_enabled", Integer, nullable=False, server_default="0"),
    Column("totp_secret", String(64)),
    Column("totp_last_counter", Integer, nullable=False, server_default="-1"),
    Column("totp_pending_secret", String(64)),
    Column("totp_enrollment_expires_at", Integer),
    Column("totp_verify_failed_at", JSON, nullable=False, server_default="[]"),
    Column("migrated_operator_epoch", String(64)),
    Column("password_updated_at", String(40)),
    Column("bootstrap_token_hash", String(64)),
    Column("bootstrap_expires_at", Float),
    Column("bootstrap_used_at", Float),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    CheckConstraint("totp_enabled IN (0, 1)", name="ck_user_credentials_totp_enabled"),
)
user_recovery_codes = Table(
    "user_recovery_codes",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("user_id", String(36), nullable=False, index=True),
    Column("code_hash", String(255), nullable=False),
    Column("used_at", String(40)),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
)
user_sessions = Table(
    "user_sessions",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("token_hash", String(64), nullable=False, unique=True, index=True),
    Column("user_id", String(36), nullable=False, index=True),
    Column("email_normalized", String(254), nullable=False),
    Column("csrf_token", String(128), nullable=False),
    Column("auth_epoch", String(64), nullable=False),
    Column("created_at", Float, nullable=False),
    Column("last_seen_at", Float, nullable=False),
    Column("expires_at", Float, nullable=False, index=True),
    Column("revoked_at", Float),
    ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
)
organization_invitations = Table(
    "organization_invitations",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("email_normalized", String(254), nullable=False),
    Column("role", String(20), nullable=False),
    Column("token_hash", String(64), nullable=False, unique=True, index=True),
    Column("invited_by_user_id", String(36), nullable=False),
    Column("status", String(20), nullable=False),
    Column("expires_at", String(40), nullable=False, index=True),
    Column("accepted_by_user_id", String(36)),
    Column("accepted_at", String(40)),
    Column("revoked_at", String(40)),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(["invited_by_user_id"], ["users.id"], ondelete="RESTRICT"),
    ForeignKeyConstraint(["accepted_by_user_id"], ["users.id"], ondelete="SET NULL"),
    CheckConstraint("role IN ('admin','member','auditor','viewer')", name="ck_org_invitation_role"),
    CheckConstraint(
        "status IN ('pending','accepted','revoked','expired')", name="ck_org_invitation_status"
    ),
)
Index(
    "ix_org_invitations_org_email",
    organization_invitations.c.organization_id,
    organization_invitations.c.email_normalized,
)
auth_lockouts = Table(
    "auth_lockouts",
    metadata,
    Column("key_hash", String(64), primary_key=True),
    Column("failure_count", Integer, nullable=False, server_default="0"),
    Column("locked_until", Float),
    Column("updated_at", Float, nullable=False),
)
# Phase 2D durable external-action attempts and worker leases.
execution_action_attempts = Table(
    "execution_action_attempts",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("job_id", String(36), nullable=False),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36), nullable=False),
    Column("action_sequence", Integer, nullable=False),
    Column("lease_generation", Integer, nullable=False),
    Column("worker_id", String(64), nullable=False),
    Column("adapter_id", String(80), nullable=False),
    Column("operation", String(80), nullable=False),
    Column("authorization_id", String(36), nullable=False),
    Column("approval_id", String(36)),
    Column("request_digest", String(64), nullable=False),
    Column("state", String(32), nullable=False),
    Column("started_at", String(40)),
    Column("completed_at", String(40)),
    Column("outcome_classification", String(40)),
    Column("result_reference", String(120)),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(["job_id"], ["execution_jobs.id"], ondelete="RESTRICT"),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="RESTRICT",
    ),
    UniqueConstraint("job_id", "action_sequence", name="uq_exec_action_job_seq"),
    CheckConstraint(
        "state IN ('not_started','authorized','in_progress','completed',"
        "'failed_before_dispatch','outcome_uncertain','reconciliation_required')",
        name="ck_exec_action_state",
    ),
)
Index(
    "ix_exec_action_job_state",
    execution_action_attempts.c.job_id,
    execution_action_attempts.c.state,
)
worker_leases = Table(
    "worker_leases",
    metadata,
    Column("worker_id", String(64), primary_key=True),
    Column("status", String(20), nullable=False),
    Column("started_at", String(40), nullable=False),
    Column("last_heartbeat_at", Float, nullable=False),
    Column("stopped_at", String(40)),
    CheckConstraint("status IN ('active','stopping','stopped')", name="ck_worker_lease_status"),
)

# Phase 6 execution assurance and evidence lifecycle governance.  These tables
# deliberately keep the organization key on every row so a missing join can
# never turn into a cross-tenant read or delete.
execution_capability_snapshots = Table(
    "execution_capability_snapshots",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("job_id", String(36)),
    Column("profile", String(24), nullable=False),
    Column("platform", String(32), nullable=False),
    Column("policy_version", String(40), nullable=False),
    Column("required_controls", JSON, nullable=False),
    Column("available_controls", JSON, nullable=False),
    Column("enforced_controls", JSON, nullable=False),
    Column("unavailable_controls", JSON, nullable=False),
    Column("initialization_status", String(24), nullable=False),
    Column("failure_reason", String(160)),
    Column("execution_identity", String(128)),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(["job_id"], ["execution_jobs.id"], ondelete="SET NULL"),
    CheckConstraint(
        "initialization_status IN ('initialized','failed','unavailable')",
        name="ck_capability_snapshot_status",
    ),
)
Index(
    "ix_capability_snapshots_org_job",
    execution_capability_snapshots.c.organization_id,
    execution_capability_snapshots.c.job_id,
)

retention_policies = Table(
    "retention_policies",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36)),
    Column("evidence_category", String(80)),
    Column("retention_days", Integer, nullable=False),
    Column("version", Integer, nullable=False, server_default="1"),
    Column("status", String(16), nullable=False),
    Column("effective_at", String(40), nullable=False),
    Column("expires_at", String(40)),
    Column("created_by", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
    ForeignKeyConstraint(
        ["engagement_id", "organization_id"],
        ["engagements.id", "engagements.organization_id"],
        ondelete="CASCADE",
    ),
    CheckConstraint("retention_days >= 1", name="ck_retention_policy_days"),
    CheckConstraint(
        "status IN ('active','expired','superseded')", name="ck_retention_policy_status"
    ),
)
Index(
    "ix_retention_policy_lookup", retention_policies.c.organization_id, retention_policies.c.status
)

legal_holds = Table(
    "legal_holds",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("engagement_id", String(36)),
    Column("reason", String(500), nullable=False),
    Column("status", String(16), nullable=False),
    Column("created_by", String(36), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("released_by", String(36)),
    Column("released_at", String(40)),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
    ForeignKeyConstraint(["released_by"], ["users.id"], ondelete="RESTRICT"),
    CheckConstraint("status IN ('active','released')", name="ck_legal_hold_status"),
)
Index("ix_legal_holds_org_status", legal_holds.c.organization_id, legal_holds.c.status)

legal_hold_records = Table(
    "legal_hold_records",
    metadata,
    Column("hold_id", String(36), primary_key=True),
    Column("record_type", String(80), primary_key=True),
    Column("record_id", String(255), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    ForeignKeyConstraint(["hold_id"], ["legal_holds.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
)
Index(
    "ix_legal_hold_records_record",
    legal_hold_records.c.organization_id,
    legal_hold_records.c.record_type,
    legal_hold_records.c.record_id,
)

retention_jobs = Table(
    "retention_jobs",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("record_type", String(80), nullable=False),
    Column("record_id", String(255), nullable=False),
    Column("status", String(20), nullable=False),
    Column("decision_reason", String(120), nullable=False),
    Column("attempt_count", Integer, nullable=False, server_default="0"),
    Column("last_error", String(500)),
    Column("created_at", String(40), nullable=False),
    Column("completed_at", String(40)),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    CheckConstraint(
        "status IN ('eligible','blocked','deleted','failed')", name="ck_retention_job_status"
    ),
    UniqueConstraint("organization_id", "record_type", "record_id", name="uq_retention_job_record"),
)
Index("ix_retention_jobs_due", retention_jobs.c.organization_id, retention_jobs.c.status)

retention_audit_events = Table(
    "retention_audit_events",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("actor_user_id", String(36), nullable=False),
    Column("action", String(80), nullable=False),
    Column("resource_type", String(80), nullable=False),
    Column("resource_id", String(255)),
    Column("details", JSON, nullable=False),
    Column("occurred_at", String(40), nullable=False),
    ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="RESTRICT"),
)
Index(
    "ix_retention_audit_org_time",
    retention_audit_events.c.organization_id,
    retention_audit_events.c.occurred_at,
)

for _operation in ("UPDATE", "DELETE"):
    event.listen(
        execution_result_provenance,
        "after_create",
        DDL(
            f"CREATE TRIGGER execution_result_provenance_no_{_operation.lower()} "
            f"BEFORE {_operation} ON execution_result_provenance "
            "BEGIN SELECT RAISE(ABORT, 'execution result provenance is immutable'); END"
        ).execute_if(dialect="sqlite"),  # type: ignore[no-untyped-call]
    )
event.listen(
    execution_result_provenance,
    "after_create",
    DDL(
        "CREATE TRIGGER execution_result_provenance_scope_guard "
        "BEFORE INSERT ON execution_result_provenance "
        "WHEN NOT EXISTS (SELECT 1 FROM execution_jobs j "
        "WHERE j.id = NEW.job_id AND j.organization_id = NEW.organization_id "
        "AND j.engagement_id = NEW.engagement_id) "
        "BEGIN SELECT RAISE(ABORT, 'execution provenance scope mismatch'); END"
    ).execute_if(dialect="sqlite"),  # type: ignore[no-untyped-call]
)


class SQLiteRepository(Repository):
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{self.path.as_posix()}"
        self._migrate(url)
        self.engine: Engine = create_engine(url)
        self._enable_foreign_keys(self.engine)
        self._initialize_context()

    def _initialize_context(self) -> None:
        """Initialize request-scoped tenant and execution authorization state."""
        self._organization_context: ContextVar[str | None] = ContextVar(
            f"chinescan_org_{id(self)}", default=None
        )
        self._execution_provenance_context: ContextVar[dict[str, Any] | None] = ContextVar(
            f"chinescan_execution_provenance_{id(self)}", default=None
        )
        self._organization_principal_id: ContextVar[str | None] = ContextVar(
            f"chinescan_org_principal_{id(self)}", default=None
        )
        self._organization_write_access: ContextVar[bool] = ContextVar(
            f"chinescan_org_write_{id(self)}", default=False
        )
        self._local_operator_organization_id: str | None = None
        self._local_operator_user_id: str | None = None
        self._bound_authorizations: list[Any] = []

    @contextmanager
    def organization_context(self, organization_id: str) -> Iterator[None]:
        """Scope repository calls to an existing active organization."""
        if not isinstance(organization_id, str) or not organization_id.strip():
            raise StorageError("A valid organization context is required.")
        with self.engine.connect() as connection:
            active = connection.execute(
                select(organizations.c.id).where(
                    organizations.c.id == organization_id,
                    organizations.c.status == "active",
                )
            ).scalar_one_or_none()
        if active is None:
            raise StorageError("The organization context is unavailable.")
        previous_organization = self._current_organization_id()
        token = self._organization_context.set(organization_id)
        # Adapter helpers may open a nested scope for the same job. Preserve an
        # already validated principal in that case; changing organizations always
        # starts with no principal and read-only access.
        same_scope = previous_organization == organization_id
        principal_token = self._organization_principal_id.set(None) if not same_scope else None
        write_token = self._organization_write_access.set(False) if not same_scope else None
        try:
            yield
        finally:
            if write_token is not None:
                self._organization_write_access.reset(write_token)
            if principal_token is not None:
                self._organization_principal_id.reset(principal_token)
            self._organization_context.reset(token)

    @contextmanager
    def member_context(
        self, organization_id: str, user_id: str, *, write: bool = False
    ) -> Iterator[None]:
        """Establish a verified active membership for organization-facing web requests."""
        if not organization_id or not user_id:
            raise StorageError("An authenticated organization membership is required.")
        with self.engine.connect() as connection:
            membership = connection.execute(
                select(organization_memberships.c.role)
                .join(
                    organizations,
                    organizations.c.id == organization_memberships.c.organization_id,
                )
                .join(users, users.c.id == organization_memberships.c.user_id)
                .where(
                    organizations.c.id == organization_id,
                    organizations.c.status == "active",
                    organization_memberships.c.user_id == user_id,
                    organization_memberships.c.status == "active",
                    users.c.status == "active",
                )
            ).scalar_one_or_none()
        if membership is None:
            raise StorageError("The organization membership is unavailable.")
        if write and membership not in {"owner", "admin", "member"}:
            raise StorageError("The organization role does not allow this action.")
        with self.organization_context(organization_id):
            token = self._organization_principal_id.set(user_id)
            write_token = self._organization_write_access.set(write)
            try:
                yield
            finally:
                self._organization_write_access.reset(write_token)
                self._organization_principal_id.reset(token)

    @contextmanager
    def local_operator_context(self) -> Iterator[None]:
        """Scope an explicitly bootstrapped local operator to their personal organization."""
        organization_id = self._local_operator_organization_id
        if not organization_id:
            raise StorageError("Local operator authorization is unavailable.")
        with self.organization_context(organization_id):
            write_token = self._organization_write_access.set(True)
            try:
                yield
            finally:
                self._organization_write_access.reset(write_token)

    def bind_local_operator_context(self) -> None:
        """Bind one repository instance for a single local CLI operation."""
        context = self.local_operator_context()
        context.__enter__()
        self._bound_authorizations.append(context)

    def bind_member_context(
        self, organization_id: str, user_id: str, *, write: bool = False
    ) -> None:
        """Bind one repository instance after CLI identity and membership validation."""
        context = self.member_context(organization_id, user_id, write=write)
        context.__enter__()
        self._bound_authorizations.append(context)

    def _current_organization_id(self) -> str | None:
        return self._organization_context.get()

    @contextmanager
    def execution_provenance_context(self, context: dict[str, Any]) -> Iterator[None]:
        """Associate only newly created result records with a validated execution job."""
        required = {
            "job_id",
            "organization_id",
            "engagement_id",
            "requester_user_id",
            "request_digest",
            "authorization_document_sha256",
        }
        if not required <= context.keys():
            raise ValueError("Execution provenance context is incomplete.")
        if context["organization_id"] != self._current_organization_id():
            raise ValueError("Execution provenance organization context does not match.")
        token = self._execution_provenance_context.set(dict(context))
        try:
            yield
        finally:
            self._execution_provenance_context.reset(token)

    def _owned_record(self, *, for_write: bool = False) -> Any:
        organization_id = self._current_organization_id()
        if organization_id is None:
            raise StorageError("Repository access requires an authorized organization context.")
        if for_write and not self._organization_write_access.get():
            raise StorageError("Repository writes require an authorized write context.")
        owner = record_ownership.alias("owned_record")
        conditions = [
            owner.c.record_type == records.c.record_type,
            owner.c.record_id == records.c.record_id,
            owner.c.organization_id == organization_id,
        ]
        principal_id = self._organization_principal_id.get()
        if principal_id is not None:
            membership = organization_memberships.alias("record_membership")
            assignment = engagement_assignments.alias("record_assignment")
            organization_roles = (
                ("owner", "admin") if for_write else ("owner", "admin", "auditor", "viewer")
            )
            organization_admin = (
                select(membership.c.id)
                .where(
                    membership.c.organization_id == owner.c.organization_id,
                    membership.c.user_id == principal_id,
                    membership.c.status == "active",
                    membership.c.role.in_(organization_roles),
                )
                .exists()
            )
            assignment_conditions = [
                assignment.c.organization_id == owner.c.organization_id,
                assignment.c.engagement_id == owner.c.engagement_id,
                assignment.c.user_id == principal_id,
                assignment.c.status == "active",
            ]
            if self._organization_write_access.get():
                assignment_conditions.append(
                    assignment.c.role.in_(("lead", "assessor", "reviewer"))
                )
            assigned_engagement = select(assignment.c.id).where(*assignment_conditions).exists()
            conditions.append(or_(organization_admin, assigned_engagement))
        return select(owner.c.record_id).where(*conditions).exists()

    def _ensure_record_ownership(
        self,
        connection: Any,
        record_type: str,
        record_id: str,
        *,
        newly_created: bool = False,
        payload: dict[str, Any] | None = None,
    ) -> None:
        organization_id = self._current_organization_id()
        if organization_id is None:
            raise StorageError("Repository writes require an authorized organization context.")
        if not self._organization_write_access.get():
            raise StorageError("Repository writes require an authorized write context.")
        provenance = self._execution_provenance_context.get()
        engagement_id = (
            provenance["engagement_id"]
            if provenance is not None and provenance["organization_id"] == organization_id
            else self._linked_engagement_id(connection, organization_id, record_type, payload)
        )
        exists = connection.execute(
            select(record_ownership.c.record_type).where(
                record_ownership.c.record_type == record_type,
                record_ownership.c.record_id == record_id,
            )
        ).first()
        if exists is None:
            from chinescan.core.organizations import now_iso

            connection.execute(
                record_ownership.insert().values(
                    record_type=record_type,
                    record_id=record_id,
                    organization_id=organization_id,
                    engagement_id=engagement_id,
                    created_at=now_iso(),
                )
            )
        if (
            newly_created
            and provenance is not None
            and record_type
            in {"scan", "finding", "evidence", "artifact", "report", "malware_analysis"}
        ):
            self._link_execution_result(connection, record_type, record_id, provenance)

    @staticmethod
    def _linked_engagement_id(
        connection: Any,
        organization_id: str,
        record_type: str,
        payload: dict[str, Any] | None,
    ) -> str | None:
        """Carry a case's engagement scope from its linked records when unambiguous."""
        if record_type != "case" or not isinstance(payload, dict):
            return None
        links = payload.get("links")
        if not isinstance(links, list):
            return None
        linked_ids = [
            (item.get("record_type"), item.get("record_id"))
            for item in links
            if isinstance(item, dict)
            and isinstance(item.get("record_type"), str)
            and isinstance(item.get("record_id"), str)
        ]
        if not linked_ids:
            return None
        scopes: set[str] = set()
        for linked_type, linked_id in linked_ids:
            engagement_id = connection.execute(
                select(record_ownership.c.engagement_id).where(
                    record_ownership.c.record_type == linked_type,
                    record_ownership.c.record_id == linked_id,
                    record_ownership.c.organization_id == organization_id,
                )
            ).scalar_one_or_none()
            if engagement_id:
                scopes.add(str(engagement_id))
        if len(scopes) > 1:
            raise StorageError("A case cannot combine records from different engagements.")
        return next(iter(scopes), None)

    @staticmethod
    def _link_execution_result(
        connection: Any, record_type: str, record_id: str, context: dict[str, Any]
    ) -> None:
        from chinescan.core.organizations import now_iso

        connection.execute(
            execution_result_provenance.insert().values(
                record_type=record_type,
                record_id=record_id,
                job_id=context["job_id"],
                organization_id=context["organization_id"],
                engagement_id=context["engagement_id"],
                created_at=now_iso(),
            )
        )
        connection.execute(
            assessment_audit_events.insert().values(
                id=str(uuid4()),
                organization_id=context["organization_id"],
                engagement_id=context["engagement_id"],
                actor_user_id=context["requester_user_id"],
                action="execution.result_linked",
                resource_type="execution_job",
                resource_id=context["job_id"],
                decision="ALLOW",
                reason_code="GOVERNED_RESULT_PROVENANCE_RECORDED",
                details={
                    "record_type": record_type,
                    "record_id": record_id,
                    "request_digest": context["request_digest"],
                },
                occurred_at=now_iso(),
            )
        )

    @staticmethod
    def _enable_foreign_keys(engine: Engine) -> None:
        """SQLite disables FK enforcement by default; enable it on each connection."""

        @event.listens_for(engine, "connect")
        def _set_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    def _migrate(self, url: str) -> None:
        """Upgrade fresh/known legacy stores; reject unknown schemas without altering them."""
        engine = create_engine(url)
        try:
            inspector = inspect(engine)
            tables = set(inspector.get_table_names()) - {"alembic_version"}
            with engine.connect() as connection:
                revision = MigrationContext.configure(connection).get_current_revision()
            if engine.dialect.name != "sqlite":
                config = self._alembic_config(url)
                command.upgrade(config, "head")
            elif revision is None and tables:
                if tables != {"records"} or not self._is_initial_records_schema(inspector):
                    raise StorageError(
                        "SQLite schema is not a recognized ChiNeScan revision; "
                        "database left unchanged."
                    )
                config = self._alembic_config(url)
                command.stamp(config, "0001_initial")
                command.upgrade(config, "head")
            else:
                config = self._alembic_config(url)
                command.upgrade(config, "head")
        except StorageError:
            raise
        except Exception as exc:
            raise StorageError(
                "Database migration failed; database contents were not recreated."
            ) from exc
        finally:
            engine.dispose()

    @staticmethod
    def _is_initial_records_schema(inspector: Inspector) -> bool:
        columns = inspector.get_columns("records")
        primary_key = inspector.get_pk_constraint("records").get("constrained_columns", [])
        return [
            (column["name"], column["type"].__class__.__name__, column["nullable"])
            for column in columns
        ] == [
            ("record_type", "VARCHAR", False),
            ("record_id", "VARCHAR", False),
            ("payload", "JSON", False),
        ] and primary_key == ["record_type", "record_id"]

    @staticmethod
    def _alembic_config(url: str) -> Config:
        project_root = Path(__file__).resolve().parents[3]
        config = Config(str(project_root / "alembic.ini"))
        config.set_main_option("script_location", str(project_root / "migrations"))
        config.set_main_option("sqlalchemy.url", url)
        return config

    def save(self, record_type: str, record_id: str, payload: dict[str, Any]) -> None:
        with self.engine.begin() as connection:
            conditions = [
                records.c.record_type == record_type,
                records.c.record_id == record_id,
            ]
            owner = self._owned_record(for_write=True)
            conditions.append(owner)
            existing = connection.execute(select(records.c.record_id).where(*conditions)).first()
            created = existing is None
            if existing:
                connection.execute(
                    records.update()
                    .where(*conditions)
                    .values(payload=json.loads(json.dumps(payload)))
                )
            else:
                connection.execute(
                    records.insert().values(
                        record_type=record_type,
                        record_id=record_id,
                        payload=json.loads(json.dumps(payload)),
                    )
                )
            self._ensure_record_ownership(
                connection, record_type, record_id, newly_created=created, payload=payload
            )

    def consume_malware_acknowledgement(
        self, token_hash: str, project_id: str, session_id: str, now: str
    ) -> str:
        """Atomically verify and consume one project/session acknowledgement."""
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                row = connection.execute(
                    select(records.c.record_id, records.c.payload).where(
                        records.c.record_type == "malware_ack",
                        records.c.record_id == token_hash,
                        self._owned_record(for_write=True),
                    )
                ).first()
                if row is None:
                    connection.commit()
                    return "missing_or_invalid"
                payload = cast(dict[str, Any], row.payload)
                if not hmac.compare_digest(str(payload.get("token_hash", "")), token_hash):
                    connection.commit()
                    return "missing_or_invalid"
                reason = (
                    "wrong_session"
                    if payload.get("session_id") != session_id
                    else "wrong_project"
                    if payload.get("project_id") != project_id
                    else "replayed"
                    if payload.get("consumed")
                    else "expired"
                    if str(payload.get("expires_at", "")) <= now
                    else ""
                )
                if not reason:
                    payload["consumed"] = True
                    connection.execute(
                        records.update()
                        .where(
                            records.c.record_type == "malware_ack",
                            records.c.record_id == token_hash,
                            self._owned_record(for_write=True),
                        )
                        .values(payload=payload)
                    )
                connection.commit()
                return reason or "consumed"
            except Exception:
                connection.rollback()
                raise

    def delete(self, record_type: str, record_id: str) -> None:
        """Delete one explicitly named record without touching related records."""
        with self.engine.begin() as connection:
            conditions = [
                records.c.record_type == record_type,
                records.c.record_id == record_id,
            ]
            owner = self._owned_record(for_write=True)
            conditions.append(owner)
            connection.execute(records.delete().where(*conditions))

    def save_many(self, items: list[tuple[str, str, dict[str, Any]]]) -> None:
        """Atomically upsert a bounded set of metadata records in one SQLite transaction."""
        if not 1 <= len(items) <= 100:
            raise ValueError("record transaction must contain between 1 and 100 records")
        with self.engine.begin() as connection:
            for record_type, record_id, payload in items:
                safe_payload = json.loads(json.dumps(payload))
                conditions = [
                    records.c.record_type == record_type,
                    records.c.record_id == record_id,
                ]
                owner = self._owned_record(for_write=True)
                conditions.append(owner)
                existing = connection.execute(
                    select(records.c.record_id).where(*conditions)
                ).first()
                created = existing is None
                if existing:
                    connection.execute(
                        records.update().where(*conditions).values(payload=safe_payload)
                    )
                else:
                    connection.execute(
                        records.insert().values(
                            record_type=record_type,
                            record_id=record_id,
                            payload=safe_payload,
                        )
                    )
                self._ensure_record_ownership(
                    connection, record_type, record_id, newly_created=created, payload=payload
                )

    def save_malware_intake(
        self,
        sample_id: str,
        sample: dict[str, Any],
        job_id: str,
        job: dict[str, Any],
        audit_id: str,
        audit: dict[str, Any],
        *,
        active_limit: int = 5,
    ) -> None:
        """Atomically reserve one of five malware slots and persist intake metadata."""
        if not 1 <= active_limit <= 5:
            raise ValueError("malware active/queue limit is invalid")
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                active = connection.execute(
                    select(func.count())
                    .select_from(records)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["status"].as_string().in_(("queued", "running")),
                        self._owned_record(for_write=True),
                    )
                ).scalar_one()
                if int(active) >= active_limit:
                    raise OverflowError("Malware queue is full.")
                for record_type, record_id, payload in (
                    ("malware_sample", sample_id, sample),
                    ("malware_job", job_id, job),
                    ("malware_audit", audit_id, audit),
                ):
                    connection.execute(
                        records.insert().values(
                            record_type=record_type,
                            record_id=record_id,
                            payload=json.loads(json.dumps(payload)),
                        )
                    )
                    self._ensure_record_ownership(connection, record_type, record_id)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def enqueue_malware_analysis(
        self,
        job_id: str,
        job: dict[str, Any],
        audit_id: str,
        audit: dict[str, Any],
        *,
        active_limit: int = 5,
    ) -> None:
        """Atomically reserve an analysis slot for an already managed sample."""
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                active = connection.execute(
                    select(func.count())
                    .select_from(records)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["status"].as_string().in_(("queued", "running")),
                        self._owned_record(for_write=True),
                    )
                ).scalar_one()
                if int(active) >= active_limit:
                    raise OverflowError("Malware queue is full.")
                duplicate = connection.execute(
                    select(func.count())
                    .select_from(records)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["sample_id"].as_string() == job.get("sample_id"),
                        records.c.payload["status"].as_string().in_(("queued", "running")),
                        self._owned_record(for_write=True),
                    )
                ).scalar_one()
                if int(duplicate):
                    raise RuntimeError("An analysis for this managed sample is already active.")
                connection.execute(
                    records.insert().values(
                        record_type="malware_job",
                        record_id=job_id,
                        payload=json.loads(json.dumps(job)),
                    )
                )
                self._ensure_record_ownership(connection, "malware_job", job_id)
                connection.execute(
                    records.insert().values(
                        record_type="malware_audit",
                        record_id=audit_id,
                        payload=json.loads(json.dumps(audit)),
                    )
                )
                self._ensure_record_ownership(connection, "malware_audit", audit_id)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def claim_next_malware_job(self, started_at: str) -> dict[str, Any] | None:
        """Claim the oldest queued job only when no other manager has a running job."""
        with self.engine.connect() as connection:
            begin_immediate(connection)
            try:
                running = connection.execute(
                    select(records.c.record_id)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["status"].as_string() == "running",
                        self._owned_record(for_write=True),
                    )
                    .limit(1)
                ).first()
                if running:
                    connection.commit()
                    return None
                row = connection.execute(
                    select(records.c.record_id, records.c.payload)
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.payload["status"].as_string() == "queued",
                        self._owned_record(for_write=True),
                    )
                    .order_by(records.c.payload["created_at"].as_string().asc())
                    .limit(1)
                ).first()
                if row is None:
                    connection.commit()
                    return None
                job = dict(row.payload)
                job["status"] = "running"
                job["started_at"] = started_at
                result = connection.execute(
                    records.update()
                    .where(
                        records.c.record_type == "malware_job",
                        records.c.record_id == row.record_id,
                        records.c.payload["status"].as_string() == "queued",
                        self._owned_record(for_write=True),
                    )
                    .values(payload=json.loads(json.dumps(job)))
                )
                if result.rowcount != 1:
                    connection.rollback()
                    return None
                connection.commit()
                return job
            except Exception:
                connection.rollback()
                raise

    def get(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        conditions = [records.c.record_type == record_type, records.c.record_id == record_id]
        owner = self._owned_record()
        conditions.append(owner)
        with self.engine.connect() as connection:
            row = connection.execute(select(records.c.payload).where(*conditions)).first()
        return dict(row[0]) if row else None

    def get_many(self, record_type: str, record_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch a bounded ID set in SQLite-safe chunks without per-record queries."""
        if len(record_ids) > 100_000:
            raise ValueError("record ID batch exceeds the supported limit")
        result: dict[str, dict[str, Any]] = {}
        owner = self._owned_record()
        with self.engine.connect() as connection:
            for start in range(0, len(record_ids), 500):
                batch = record_ids[start : start + 500]
                conditions = [
                    records.c.record_type == record_type,
                    records.c.record_id.in_(batch),
                ]
                conditions.append(owner)
                rows = connection.execute(
                    select(records.c.record_id, records.c.payload).where(*conditions)
                )
                result.update({str(row[0]): dict(row[1]) for row in rows})
        return result

    def list_records(self, record_type: str) -> list[dict[str, Any]]:
        """Return payloads for one record type from the local SQLite store."""
        conditions = [records.c.record_type == record_type]
        owner = self._owned_record()
        conditions.append(owner)
        with self.engine.connect() as connection:
            rows = connection.execute(select(records.c.payload).where(*conditions)).all()
        return [dict(row[0]) for row in rows]

    def page_records(
        self,
        record_type: str,
        *,
        limit: int,
        offset: int,
        sort_by: str,
        descending: bool,
        filters: dict[str, str] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Fetch a bounded JSON-record page using a caller-allowlisted field set."""
        if not 1 <= limit <= 100 or not 0 <= offset <= 100_000:
            raise ValueError("page bounds are invalid")
        allowed = {
            "scan": {"started_at", "status", "scanner"},
            "finding": {"severity", "title", "scanner", "category"},
            "case": {"created_at", "updated_at", "status", "severity", "title"},
            "log_job": {"created_at", "status", "source_id"},
            "malware_job": {"created_at", "status", "sample_id"},
        }
        if sort_by not in allowed.get(record_type, set()):
            raise ValueError("record sort field is not allowed")
        conditions = [records.c.record_type == record_type]
        owner = self._owned_record()
        conditions.append(owner)
        for field, value in (filters or {}).items():
            if field not in allowed.get(record_type, set()):
                raise ValueError("record filter field is not allowed")
            json_value = records.c.payload[field].as_string()
            conditions.append(func.lower(json_value) == value.lower())
        sort_value = records.c.payload[sort_by].as_string()
        if record_type == "finding" and sort_by == "severity":
            sort_value = case(
                (func.lower(sort_value) == "critical", 5),
                (func.lower(sort_value) == "high", 4),
                (func.lower(sort_value) == "medium", 3),
                (func.lower(sort_value) == "low", 2),
                (func.lower(sort_value) == "info", 1),
                else_=0,
            )
        ordering = sort_value.desc() if descending else sort_value.asc()
        with self.engine.connect() as connection:
            total = int(
                connection.execute(
                    select(func.count()).select_from(records).where(*conditions)
                ).scalar_one()
            )
            rows = connection.execute(
                select(records.c.payload)
                .where(*conditions)
                .order_by(ordering, records.c.record_id.asc())
                .limit(limit)
                .offset(offset)
            ).all()
        return [dict(row[0]) for row in rows], total

    @overload
    def count_records(self, record_type: str, *, group_by: None = None) -> int: ...

    @overload
    def count_records(self, record_type: str, *, group_by: str) -> dict[str, int]: ...

    def count_records(
        self, record_type: str, *, group_by: str | None = None
    ) -> int | dict[str, int]:
        """Count records or group by an explicitly supported summary field."""
        allowed_groups = {"finding": {"severity", "verdict"}, "scan": set()}
        if group_by is None:
            conditions = [records.c.record_type == record_type]
            owner = self._owned_record()
            conditions.append(owner)
            with self.engine.connect() as connection:
                return int(
                    connection.execute(
                        select(func.count()).select_from(records).where(*conditions)
                    ).scalar_one()
                )
        if group_by not in allowed_groups.get(record_type, set()):
            raise ValueError("record summary field is not allowed")
        field = func.json_extract(records.c.payload, f"$.{group_by}")
        conditions = [records.c.record_type == record_type]
        owner = self._owned_record()
        conditions.append(owner)
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(field, func.count()).where(*conditions).group_by(field)
            ).all()
        return {str(key): int(cast(Any, count)) for key, count in rows if key is not None}

    def close(self) -> None:
        while self._bound_authorizations:
            self._bound_authorizations.pop().__exit__(None, None, None)
        self.engine.dispose()
