"""Add durable worker leases, fencing, action attempts, and reconciliation status."""
# ruff: noqa: E501

import sqlalchemy as sa
from alembic import op

revision = "0015_durable_job_leases_actions"
down_revision = "0014_multi_user_identity_sessions"
branch_labels = None
depends_on = None

_EXECUTION_JOB_TRIGGERS_OLD = (
    "execution_job_context_immutable",
    "execution_job_state_transition",
    "execution_job_no_delete",
    "execution_job_auth_document_immutable",
    "execution_job_malware_binding_immutable",
    "execution_result_provenance_scope_guard",
)


def _drop_execution_job_triggers() -> None:
    for name in _EXECUTION_JOB_TRIGGERS_OLD:
        op.execute(f'DROP TRIGGER IF EXISTS "{name}"')


def _create_execution_job_triggers(*, include_reconciliation: bool) -> None:
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
    if include_reconciliation:
        op.execute(
            """
            CREATE TRIGGER execution_job_state_transition
            BEFORE UPDATE OF status ON execution_jobs
            WHEN NOT (
              (OLD.status = 'queued' AND NEW.status IN ('claimed','blocked','cancelled')) OR
              (OLD.status = 'claimed' AND NEW.status IN ('queued','running','blocked','cancelled','failed','reconciliation_required')) OR
              (OLD.status = 'running' AND NEW.status IN ('queued','completed','blocked','cancelled','failed','reconciliation_required')) OR
              (OLD.status = 'reconciliation_required' AND NEW.status IN ('completed','failed','blocked','cancelled'))
            )
            BEGIN SELECT RAISE(ABORT, 'invalid execution job state transition'); END
            """
        )
    else:
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
    op.execute(
        """
        CREATE TRIGGER execution_job_auth_document_immutable
        BEFORE UPDATE ON execution_jobs
        WHEN COALESCE(NEW.authorization_document_sha256, '')
          != COALESCE(OLD.authorization_document_sha256, '')
        BEGIN SELECT RAISE(ABORT, 'execution authorization digest is immutable'); END
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_job_malware_binding_immutable
        BEFORE UPDATE ON execution_jobs
        WHEN COALESCE(NEW.malware_evidence_snapshot_id, '') != COALESCE(OLD.malware_evidence_snapshot_id, '')
          OR COALESCE(NEW.malware_evidence_sha256, '') != COALESCE(OLD.malware_evidence_sha256, '')
          OR COALESCE(NEW.malware_evidence_manifest_sha256, '') != COALESCE(OLD.malware_evidence_manifest_sha256, '')
          OR COALESCE(NEW.malware_evidence_manifest_version, 0) != COALESCE(OLD.malware_evidence_manifest_version, 0)
          OR COALESCE(NEW.malware_analysis_version, '') != COALESCE(OLD.malware_analysis_version, '')
        BEGIN SELECT RAISE(ABORT, 'execution malware evidence binding is immutable'); END
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_result_provenance_scope_guard
        BEFORE INSERT ON execution_result_provenance
        WHEN NOT EXISTS (
          SELECT 1 FROM execution_jobs j
          WHERE j.id = NEW.job_id
            AND j.organization_id = NEW.organization_id
            AND j.engagement_id = NEW.engagement_id
        )
        BEGIN SELECT RAISE(ABORT, 'execution provenance scope mismatch'); END
        """
    )


def _recreate_execution_jobs_status(
    *, status_type_len: int, status_check: str, include_reconciliation: bool
) -> None:
    bind = op.get_bind()
    _drop_execution_job_triggers()

    def _alter() -> None:
        with op.batch_alter_table("execution_jobs", recreate="always") as batch:
            batch.alter_column(
                "status",
                existing_type=sa.String(20 if include_reconciliation else 24),
                type_=sa.String(status_type_len),
                existing_nullable=False,
            )
            batch.drop_constraint("ck_execution_job_status", type_="check")
            batch.create_check_constraint("ck_execution_job_status", status_check)

    if bind.dialect.name == "sqlite":
        fk_enabled = bool(bind.execute(sa.text("PRAGMA foreign_keys")).scalar())
        with op.get_context().autocommit_block():
            if fk_enabled:
                bind.execute(sa.text("PRAGMA foreign_keys=OFF"))
            try:
                _alter()
            finally:
                if fk_enabled:
                    bind.execute(sa.text("PRAGMA foreign_keys=ON"))
    else:
        _alter()
    _create_execution_job_triggers(include_reconciliation=include_reconciliation)


def upgrade() -> None:
    for _name, column in (
        ("worker_id", sa.Column("worker_id", sa.String(64))),
        (
            "lease_generation",
            sa.Column("lease_generation", sa.Integer, nullable=False, server_default="0"),
        ),
        ("lease_expires_at", sa.Column("lease_expires_at", sa.Float)),
        ("heartbeat_at", sa.Column("heartbeat_at", sa.Float)),
        ("claimed_at", sa.Column("claimed_at", sa.String(40))),
        (
            "attempt_number",
            sa.Column("attempt_number", sa.Integer, nullable=False, server_default="0"),
        ),
        ("last_recovery_at", sa.Column("last_recovery_at", sa.String(40))),
    ):
        op.add_column("execution_jobs", column)

    _recreate_execution_jobs_status(
        status_type_len=24,
        status_check=(
            "status IN ('queued','claimed','running','completed','blocked',"
            "'cancelled','failed','reconciliation_required')"
        ),
        include_reconciliation=True,
    )
    op.create_index(
        "ix_execution_jobs_lease_expiry",
        "execution_jobs",
        ["status", "lease_expires_at"],
    )

    op.create_table(
        "execution_action_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("action_sequence", sa.Integer, nullable=False),
        sa.Column("lease_generation", sa.Integer, nullable=False),
        sa.Column("worker_id", sa.String(64), nullable=False),
        sa.Column("adapter_id", sa.String(80), nullable=False),
        sa.Column("operation", sa.String(80), nullable=False),
        sa.Column("authorization_id", sa.String(36), nullable=False),
        sa.Column("approval_id", sa.String(36)),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("started_at", sa.String(40)),
        sa.Column("completed_at", sa.String(40)),
        sa.Column("outcome_classification", sa.String(40)),
        sa.Column("result_reference", sa.String(120)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["execution_jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("job_id", "action_sequence", name="uq_exec_action_job_seq"),
        sa.CheckConstraint(
            "state IN ('not_started','authorized','in_progress','completed',"
            "'failed_before_dispatch','outcome_uncertain','reconciliation_required')",
            name="ck_exec_action_state",
        ),
    )
    op.create_index(
        "ix_exec_action_job_state",
        "execution_action_attempts",
        ["job_id", "state"],
    )
    op.execute(
        """
        CREATE TRIGGER execution_action_attempt_context_immutable
        BEFORE UPDATE ON execution_action_attempts
        WHEN NEW.job_id != OLD.job_id
          OR NEW.organization_id != OLD.organization_id
          OR NEW.engagement_id != OLD.engagement_id
          OR NEW.action_sequence != OLD.action_sequence
          OR NEW.lease_generation != OLD.lease_generation
          OR NEW.worker_id != OLD.worker_id
          OR NEW.adapter_id != OLD.adapter_id
          OR NEW.operation != OLD.operation
          OR NEW.authorization_id != OLD.authorization_id
          OR COALESCE(NEW.approval_id, '') != COALESCE(OLD.approval_id, '')
          OR NEW.request_digest != OLD.request_digest
        BEGIN SELECT RAISE(ABORT, 'execution action attempt context is immutable'); END
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_action_attempt_no_delete
        BEFORE DELETE ON execution_action_attempts
        BEGIN SELECT RAISE(ABORT, 'execution action attempt history is retained'); END
        """
    )

    op.create_table(
        "worker_leases",
        sa.Column("worker_id", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("last_heartbeat_at", sa.Float, nullable=False),
        sa.Column("stopped_at", sa.String(40)),
        sa.CheckConstraint(
            "status IN ('active','stopping','stopped')",
            name="ck_worker_lease_status",
        ),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM execution_action_attempts")).scalar_one():
        raise RuntimeError(
            "Durable external-action history exists; use a forward migration to preserve it."
        )
    if bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM execution_jobs "
            "WHERE status = 'reconciliation_required' OR attempt_number > 0"
        )
    ).scalar_one():
        raise RuntimeError(
            "Durable worker lease or reconciliation history exists; "
            "use a forward migration to preserve it."
        )

    op.drop_table("worker_leases")
    op.execute('DROP TRIGGER IF EXISTS "execution_action_attempt_no_delete"')
    op.execute('DROP TRIGGER IF EXISTS "execution_action_attempt_context_immutable"')
    op.drop_index("ix_exec_action_job_state", table_name="execution_action_attempts")
    op.drop_table("execution_action_attempts")
    op.drop_index("ix_execution_jobs_lease_expiry", table_name="execution_jobs")

    _recreate_execution_jobs_status(
        status_type_len=20,
        status_check=(
            "status IN ('queued','claimed','running','completed','blocked','cancelled','failed')"
        ),
        include_reconciliation=False,
    )
    for col in (
        "last_recovery_at",
        "attempt_number",
        "claimed_at",
        "heartbeat_at",
        "lease_expires_at",
        "lease_generation",
        "worker_id",
    ):
        op.drop_column("execution_jobs", col)
