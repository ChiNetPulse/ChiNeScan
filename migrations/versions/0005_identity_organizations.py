"""Add persistent identities, tenant foundation, and generic-record ownership."""

import sqlalchemy as sa
from alembic import op

revision = "0005_identity_organizations"
down_revision = "0004_dashboard_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email_normalized", sa.String(254), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("auth_epoch", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.UniqueConstraint("email_normalized", name="uq_users_email_normalized"),
        sa.CheckConstraint("status IN ('active','suspended','archived')", name="ck_users_status"),
    )
    op.create_index("ix_users_email_normalized", "users", ["email_normalized"], unique=True)
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("owner_user_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("slug", name="uq_organizations_slug"),
        sa.CheckConstraint(
            "status IN ('active','suspended','archived')", name="ck_organizations_status"
        ),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)
    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_membership_org_user"),
        sa.CheckConstraint(
            "role IN ('owner','admin','member','auditor','viewer')", name="ck_membership_role"
        ),
        sa.CheckConstraint(
            "status IN ('active','suspended','revoked')", name="ck_membership_status"
        ),
    )
    op.create_index("ix_memberships_org", "organization_memberships", ["organization_id"])
    op.create_index("ix_memberships_user", "organization_memberships", ["user_id"])
    op.create_table(
        "clients",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(2000)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("id", "organization_id", name="uq_client_id_org"),
        sa.CheckConstraint("status IN ('active','archived')", name="ck_clients_status"),
    )
    op.create_index("ix_clients_org", "clients", ["organization_id"])
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("client_id", sa.String(36)),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["client_id", "organization_id"],
            ["clients.id", "clients.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_engagement_id_org"),
        sa.CheckConstraint(
            "status IN ('draft','active','paused','completed','archived')",
            name="ck_engagement_status",
        ),
    )
    op.create_index("ix_engagements_org", "engagements", ["organization_id"])
    op.create_index("ix_engagements_client", "engagements", ["client_id"])
    op.create_table(
        "engagement_assignments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("engagement_id", "user_id", name="uq_assignment_engagement_user"),
        sa.CheckConstraint(
            "role IN ('lead','assessor','reviewer','observer')", name="ck_assignment_role"
        ),
        sa.CheckConstraint("status IN ('active','revoked')", name="ck_assignment_status"),
    )
    op.create_index("ix_assignments_org", "engagement_assignments", ["organization_id"])
    op.create_index("ix_assignments_engagement", "engagement_assignments", ["engagement_id"])
    op.create_index("ix_assignments_user", "engagement_assignments", ["user_id"])
    op.create_table(
        "record_ownership",
        sa.Column("record_type", sa.String(80), primary_key=True),
        sa.Column("record_id", sa.String(255), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            ["record_type", "record_id"],
            ["records.record_type", "records.record_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_record_ownership_org", "record_ownership", ["organization_id"])
    op.create_table(
        "organization_bootstrap_reports",
        sa.Column("report_id", sa.String(80), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "organization_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("actor_user_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(40), nullable=False),
        sa.Column("resource_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="RESTRICT"),
    )
    op.create_index(
        "ix_org_audit_org_created", "organization_audit_events", ["organization_id", "created_at"]
    )


def downgrade() -> None:
    connection = op.get_bind()
    for table in (
        "organization_audit_events",
        "organization_bootstrap_reports",
        "record_ownership",
        "engagement_assignments",
        "engagements",
        "clients",
        "organization_memberships",
        "organizations",
        "users",
    ):
        if connection.execute(sa.text(f'SELECT COUNT(*) FROM "{table}"')).scalar_one():
            raise RuntimeError(
                "Phase 1B data exists; restore a verified backup or use a forward migration."
            )
    op.drop_index("ix_org_audit_org_created", table_name="organization_audit_events")
    op.drop_table("organization_audit_events")
    op.drop_table("organization_bootstrap_reports")
    op.drop_table("record_ownership")
    op.drop_index("ix_assignments_user", table_name="engagement_assignments")
    op.drop_index("ix_assignments_engagement", table_name="engagement_assignments")
    op.drop_index("ix_assignments_org", table_name="engagement_assignments")
    op.drop_table("engagement_assignments")
    op.drop_index("ix_engagements_client", table_name="engagements")
    op.drop_index("ix_engagements_org", table_name="engagements")
    op.drop_table("engagements")
    op.drop_index("ix_clients_org", table_name="clients")
    op.drop_table("clients")
    op.drop_index("ix_memberships_user", table_name="organization_memberships")
    op.drop_index("ix_memberships_org", table_name="organization_memberships")
    op.drop_table("organization_memberships")
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_table("organizations")
    op.drop_index("ix_users_email_normalized", table_name="users")
    op.drop_table("users")
