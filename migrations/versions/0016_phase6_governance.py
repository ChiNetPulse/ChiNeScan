"""Add Phase 6 capability snapshots and governed evidence lifecycle tables."""

import sqlalchemy as sa
from alembic import op

revision = "0016_phase6_governance"
down_revision = "0015_durable_job_leases_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Phase 6 first-administrator bootstrap state is part of this revision so
    # existing SQLite/PostgreSQL deployments receive the same schema as the
    # reviewed Supabase baseline.
    op.add_column(
        "users",
        sa.Column(
            "platform_role",
            sa.String(20),
            sa.CheckConstraint(
                "platform_role IN ('user', 'superuser')", name="ck_users_platform_role"
            ),
            nullable=False,
            server_default=sa.text("'user'"),
        ),
    )
    op.add_column("user_credentials", sa.Column("bootstrap_token_hash", sa.String(64)))
    op.add_column("user_credentials", sa.Column("bootstrap_expires_at", sa.Float()))
    op.add_column("user_credentials", sa.Column("bootstrap_used_at", sa.Float()))
    op.create_table(
        "execution_capability_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(36)),
        sa.Column("profile", sa.String(24), nullable=False),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("policy_version", sa.String(40), nullable=False),
        sa.Column("required_controls", sa.JSON, nullable=False),
        sa.Column("available_controls", sa.JSON, nullable=False),
        sa.Column("enforced_controls", sa.JSON, nullable=False),
        sa.Column("unavailable_controls", sa.JSON, nullable=False),
        sa.Column("initialization_status", sa.String(24), nullable=False),
        sa.Column("failure_reason", sa.String(160)),
        sa.Column("execution_identity", sa.String(128)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["job_id"], ["execution_jobs.id"], ondelete="SET NULL"),
        sa.CheckConstraint(
            "initialization_status IN ('initialized','failed','unavailable')",
            name="ck_capability_snapshot_status",
        ),
    )
    op.create_index(
        "ix_capability_snapshots_org_job",
        "execution_capability_snapshots",
        ["organization_id", "job_id"],
    )
    op.create_table(
        "retention_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36)),
        sa.Column("evidence_category", sa.String(80)),
        sa.Column("retention_days", sa.Integer, nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("effective_at", sa.String(40), nullable=False),
        sa.Column("expires_at", sa.String(40)),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("retention_days >= 1", name="ck_retention_policy_days"),
        sa.CheckConstraint(
            "status IN ('active','expired','superseded')", name="ck_retention_policy_status"
        ),
    )
    op.create_index(
        "ix_retention_policy_lookup", "retention_policies", ["organization_id", "status"]
    )
    op.create_table(
        "legal_holds",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36)),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("released_by", sa.String(36)),
        sa.Column("released_at", sa.String(40)),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["released_by"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("status IN ('active','released')", name="ck_legal_hold_status"),
    )
    op.create_index("ix_legal_holds_org_status", "legal_holds", ["organization_id", "status"])
    op.create_table(
        "legal_hold_records",
        sa.Column("hold_id", sa.String(36), primary_key=True),
        sa.Column("record_type", sa.String(80), primary_key=True),
        sa.Column("record_id", sa.String(255), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(["hold_id"], ["legal_holds.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_legal_hold_records_record",
        "legal_hold_records",
        ["organization_id", "record_type", "record_id"],
    )
    op.create_table(
        "retention_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("record_type", sa.String(80), nullable=False),
        sa.Column("record_id", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("decision_reason", sa.String(120), nullable=False),
        sa.Column("attempt_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(500)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("completed_at", sa.String(40)),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "status IN ('eligible','blocked','deleted','failed')", name="ck_retention_job_status"
        ),
        sa.UniqueConstraint(
            "organization_id", "record_type", "record_id", name="uq_retention_job_record"
        ),
    )
    op.create_index("ix_retention_jobs_due", "retention_jobs", ["organization_id", "status"])
    op.create_table(
        "retention_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("actor_user_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource_id", sa.String(255)),
        sa.Column("details", sa.JSON, nullable=False),
        sa.Column("occurred_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="RESTRICT"),
    )
    op.create_index(
        "ix_retention_audit_org_time", "retention_audit_events", ["organization_id", "occurred_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_retention_audit_org_time", table_name="retention_audit_events")
    op.drop_table("retention_audit_events")
    op.drop_index("ix_retention_jobs_due", table_name="retention_jobs")
    op.drop_table("retention_jobs")
    op.drop_index("ix_legal_hold_records_record", table_name="legal_hold_records")
    op.drop_table("legal_hold_records")
    op.drop_index("ix_legal_holds_org_status", table_name="legal_holds")
    op.drop_table("legal_holds")
    op.drop_index("ix_retention_policy_lookup", table_name="retention_policies")
    op.drop_table("retention_policies")
    op.drop_index("ix_capability_snapshots_org_job", table_name="execution_capability_snapshots")
    op.drop_table("execution_capability_snapshots")
    op.drop_column("user_credentials", "bootstrap_used_at")
    op.drop_column("user_credentials", "bootstrap_expires_at")
    op.drop_column("user_credentials", "bootstrap_token_hash")
    op.drop_column("users", "platform_role")
