"""Add immutable links from governed jobs to their result records."""

import sqlalchemy as sa
from alembic import op

revision = "0009_execution_result_provenance"
down_revision = "0008_execution_cancellation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "execution_jobs",
        sa.Column("authorization_document_sha256", sa.String(64), nullable=True),
    )
    op.create_table(
        "execution_result_provenance",
        sa.Column("record_type", sa.String(80), nullable=False),
        sa.Column("record_id", sa.String(255), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "record_type IN ('scan','finding','evidence','artifact','report')",
            name="ck_execution_result_provenance_type",
        ),
        sa.ForeignKeyConstraint(
            ["record_type", "record_id"],
            ["records.record_type", "records.record_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["job_id"], ["execution_jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("record_type", "record_id"),
    )
    op.create_index(
        "ix_execution_result_provenance_job",
        "execution_result_provenance",
        ["job_id", "organization_id", "engagement_id"],
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
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            f"""
            CREATE TRIGGER execution_result_provenance_no_{operation.lower()}
            BEFORE {operation} ON execution_result_provenance
            BEGIN SELECT RAISE(ABORT, 'execution result provenance is immutable'); END
            """
        )


def downgrade() -> None:
    connection = op.get_bind()
    links = connection.execute(
        sa.text("SELECT COUNT(*) FROM execution_result_provenance")
    ).scalar_one()
    digests = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM execution_jobs "
            "WHERE authorization_document_sha256 IS NOT NULL"
        )
    ).scalar_one()
    if links or digests:
        raise RuntimeError(
            "Execution provenance exists; use a forward migration to preserve its history."
        )
    for trigger in (
        "execution_result_provenance_no_update",
        "execution_result_provenance_no_delete",
        "execution_result_provenance_scope_guard",
        "execution_job_auth_document_immutable",
    ):
        op.execute(f'DROP TRIGGER IF EXISTS "{trigger}"')
    op.drop_index(
        "ix_execution_result_provenance_job", table_name="execution_result_provenance"
    )
    op.drop_table("execution_result_provenance")
    op.drop_column("execution_jobs", "authorization_document_sha256")
