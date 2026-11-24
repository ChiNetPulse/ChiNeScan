"""Persist governed execution cancellation requests and worker observation."""

import sqlalchemy as sa
from alembic import op

revision = "0008_execution_cancellation"
down_revision = "0007_governed_execution_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("execution_jobs", sa.Column("cancellation_requested_at", sa.String(40)))
    op.add_column("execution_jobs", sa.Column("cancellation_requested_by", sa.String(36)))
    op.add_column("execution_jobs", sa.Column("cancellation_observed_at", sa.String(40)))


def downgrade() -> None:
    connection = op.get_bind()
    if connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM execution_jobs WHERE cancellation_requested_at IS NOT NULL "
            "OR cancellation_requested_by IS NOT NULL OR cancellation_observed_at IS NOT NULL"
        )
    ).scalar_one():
        raise RuntimeError("Cancellation history exists; use a forward migration to preserve it.")
    op.drop_column("execution_jobs", "cancellation_observed_at")
    op.drop_column("execution_jobs", "cancellation_requested_by")
    op.drop_column("execution_jobs", "cancellation_requested_at")
