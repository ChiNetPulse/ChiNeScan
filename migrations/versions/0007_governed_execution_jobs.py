"""Add durable engagement-governed execution jobs."""

import sqlalchemy as sa
from alembic import op

revision = "0007_governed_execution_jobs"
down_revision = "0006_engagement_scope_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "uq_engagement_asset_id_org_engagement",
        "engagement_assets",
        ["id", "organization_id", "engagement_id"],
        unique=True,
    )
    op.create_index(
        "uq_approval_id_org", "approval_requests", ["id", "organization_id"], unique=True
    )
    op.create_table(
        "execution_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("requester_user_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("target", sa.String(2048), nullable=False),
        sa.Column("asset_type", sa.String(20), nullable=False),
        sa.Column("technique", sa.String(80), nullable=False),
        sa.Column("action_class", sa.String(24), nullable=False),
        sa.Column("scope_revision_id", sa.String(36), nullable=False),
        sa.Column("authorization_id", sa.String(36), nullable=False),
        sa.Column("approval_id", sa.String(36)),
        sa.Column("policy_decision_id", sa.String(36), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("execution_context", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.Column("started_at", sa.String(40)),
        sa.Column("finished_at", sa.String(40)),
        sa.Column("scan_id", sa.String(36)),
        sa.Column("result_summary", sa.JSON()),
        sa.Column("approval_consumed_at", sa.String(40)),
        sa.Column("error_code", sa.String(80)),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "requester_user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id", "engagement_id"],
            [
                "engagement_assets.id",
                "engagement_assets.organization_id",
                "engagement_assets.engagement_id",
            ],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scope_revision_id", "organization_id"],
            ["scope_revisions.id", "scope_revisions.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["authorization_id", "organization_id"],
            ["authorization_records.id", "authorization_records.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approval_id", "organization_id"],
            ["approval_requests.id", "approval_requests.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('queued','claimed','running','completed','blocked','cancelled','failed')",
            name="ck_execution_job_status",
        ),
        sa.CheckConstraint(
            "action_class IN ('passive','controlled_active','sensitive')",
            name="ck_execution_job_action_class",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "engagement_id",
            "requester_user_id",
            "idempotency_key",
            name="uq_execution_job_idempotency",
        ),
    )
    op.create_index(
        "ix_execution_jobs_org_status_created",
        "execution_jobs",
        ["organization_id", "status", "created_at"],
    )
    op.create_index("ix_execution_jobs_queue", "execution_jobs", ["status", "created_at"])
    op.create_index(
        "uq_execution_job_approval_binding",
        "execution_jobs",
        ["approval_id"],
        unique=True,
        sqlite_where=sa.text("approval_id IS NOT NULL"),
    )
    op.execute(
        """
        CREATE TRIGGER execution_job_context_immutable
        BEFORE UPDATE ON execution_jobs
        WHEN NEW.organization_id != OLD.organization_id
          OR NEW.engagement_id != OLD.engagement_id
          OR NEW.requester_user_id != OLD.requester_user_id
          OR NEW.asset_id != OLD.asset_id
          OR NEW.target != OLD.target
          OR NEW.asset_type != OLD.asset_type
          OR NEW.technique != OLD.technique
          OR NEW.action_class != OLD.action_class
          OR NEW.scope_revision_id != OLD.scope_revision_id
          OR NEW.authorization_id != OLD.authorization_id
          OR COALESCE(NEW.approval_id, '') != COALESCE(OLD.approval_id, '')
          OR NEW.policy_decision_id != OLD.policy_decision_id
          OR NEW.request_digest != OLD.request_digest
          OR NEW.execution_context != OLD.execution_context
        BEGIN SELECT RAISE(ABORT, 'execution context is immutable'); END
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_job_state_transition
        BEFORE UPDATE OF status ON execution_jobs
        WHEN NOT (
          (OLD.status = 'queued' AND NEW.status IN ('claimed','blocked','cancelled')) OR
          (OLD.status = 'claimed' AND NEW.status IN ('running','blocked','cancelled','failed')) OR
          (OLD.status = 'running' AND NEW.status IN ('completed','blocked','cancelled','failed'))
        )
        BEGIN SELECT RAISE(ABORT, 'invalid execution job state transition'); END
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_job_no_delete
        BEFORE DELETE ON execution_jobs
        BEGIN SELECT RAISE(ABORT, 'execution jobs are retained'); END
        """
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT COUNT(*) FROM execution_jobs")).scalar_one():
        raise RuntimeError(
            "Execution job data exists; restore a verified backup or use a forward migration."
        )
    for trigger in (
        "execution_job_no_delete",
        "execution_job_state_transition",
        "execution_job_context_immutable",
    ):
        op.execute(f'DROP TRIGGER IF EXISTS "{trigger}"')
    op.drop_index("ix_execution_jobs_queue", table_name="execution_jobs")
    op.drop_index("ix_execution_jobs_org_status_created", table_name="execution_jobs")
    op.drop_index("uq_execution_job_approval_binding", table_name="execution_jobs")
    op.drop_table("execution_jobs")
    op.drop_index("uq_approval_id_org", table_name="approval_requests")
    op.drop_index("uq_engagement_asset_id_org_engagement", table_name="engagement_assets")
