"""Add engagement-owned immutable log evidence snapshots."""

import sqlalchemy as sa
from alembic import op

revision = "0011_governed_log_evidence"
down_revision = "0010_governed_repository_assets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("PRAGMA defer_foreign_keys=ON")
    with op.batch_alter_table("engagement_assets", recreate="always") as batch:
        batch.drop_constraint("ck_asset_type", type_="check")
        batch.create_check_constraint(
            "ck_asset_type",
            "asset_type IN ('domain','ip','cidr','url','repository','log_evidence')",
        )

    op.create_table(
        "log_evidence_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("registered_by", sa.String(36), nullable=False),
        sa.Column("source_format", sa.String(24), nullable=False),
        sa.Column("label", sa.String(120), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("legal_hold", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hold_reason", sa.String(500)),
        sa.Column("deleted_at", sa.String(40)),
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
            ["organization_id", "registered_by"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "id", "organization_id", "engagement_id", "asset_id",
            name="uq_log_snapshot_scope",
        ),
        sa.UniqueConstraint("asset_id", name="uq_log_snapshot_asset"),
        sa.CheckConstraint(
            "size_bytes BETWEEN 0 AND 250000000", name="ck_log_snapshot_size"
        ),
        sa.CheckConstraint("file_count BETWEEN 1 AND 10000", name="ck_log_snapshot_file_count"),
        sa.CheckConstraint("manifest_version = 1", name="ck_log_manifest_version"),
        sa.CheckConstraint(
            "status IN ('available','missing','corrupt','deleted')",
            name="ck_log_snapshot_status",
        ),
        sa.CheckConstraint("legal_hold IN (0,1)", name="ck_log_snapshot_hold"),
    )
    op.create_index(
        "ix_log_snapshot_tenant", "log_evidence_snapshots", ["organization_id", "engagement_id"]
    )
    op.create_table(
        "log_evidence_quota_reservations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("reserved_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "reserved_bytes BETWEEN 0 AND 250000000", name="ck_log_reservation_bytes"
        ),
    )
    op.create_index(
        "ix_log_reservation_org", "log_evidence_quota_reservations", ["organization_id"]
    )

    op.add_column("execution_jobs", sa.Column("log_evidence_snapshot_id", sa.String(36)))
    op.add_column("execution_jobs", sa.Column("log_evidence_sha256", sa.String(64)))
    op.add_column("execution_jobs", sa.Column("log_evidence_manifest_version", sa.Integer()))
    op.add_column("execution_jobs", sa.Column("log_evidence_source_format", sa.String(24)))
    op.add_column("execution_jobs", sa.Column("log_analysis_version", sa.String(80)))
    op.add_column("execution_jobs", sa.Column("log_ruleset_version", sa.String(80)))
    op.execute('DROP TRIGGER IF EXISTS "execution_job_auth_document_immutable"')
    op.execute('DROP TRIGGER IF EXISTS "execution_result_provenance_scope_guard"')
    op.execute("PRAGMA defer_foreign_keys=ON")
    with op.batch_alter_table("execution_jobs", recreate="always") as batch:
        batch.create_foreign_key(
            "fk_job_log_evidence_snapshot_scope",
            "log_evidence_snapshots",
            ["log_evidence_snapshot_id", "organization_id", "engagement_id", "asset_id"],
            ["id", "organization_id", "engagement_id", "asset_id"],
            ondelete="RESTRICT",
        )
    _restore_execution_triggers()
    op.execute("""
        CREATE TRIGGER log_evidence_snapshot_metadata_immutable
        BEFORE UPDATE ON log_evidence_snapshots
        WHEN NEW.sha256 != OLD.sha256 OR NEW.size_bytes != OLD.size_bytes
          OR NEW.file_count != OLD.file_count OR NEW.manifest != OLD.manifest
          OR NEW.manifest_version != OLD.manifest_version OR NEW.created_at != OLD.created_at
          OR NEW.asset_id != OLD.asset_id OR NEW.organization_id != OLD.organization_id
          OR NEW.engagement_id != OLD.engagement_id OR NEW.registered_by != OLD.registered_by
        BEGIN SELECT RAISE(ABORT, 'log evidence snapshot provenance is immutable'); END
    """)


def _restore_execution_triggers() -> None:
    op.execute("""
        CREATE TRIGGER execution_job_auth_document_immutable
        BEFORE UPDATE ON execution_jobs
        WHEN COALESCE(NEW.authorization_document_sha256, '')
          != COALESCE(OLD.authorization_document_sha256, '')
        BEGIN SELECT RAISE(ABORT, 'execution authorization digest is immutable'); END
    """)
    op.execute("""
        CREATE TRIGGER execution_result_provenance_scope_guard
        BEFORE INSERT ON execution_result_provenance
        WHEN NOT EXISTS (
          SELECT 1 FROM execution_jobs j
          WHERE j.id = NEW.job_id
            AND j.organization_id = NEW.organization_id
            AND j.engagement_id = NEW.engagement_id
        )
        BEGIN SELECT RAISE(ABORT, 'execution provenance scope mismatch'); END
    """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM log_evidence_snapshots")).scalar_one():
        raise RuntimeError("Log evidence history exists; use a forward migration to preserve it.")
    jobs = bind.execute(sa.text(
        "SELECT COUNT(*) FROM execution_jobs WHERE log_evidence_snapshot_id IS NOT NULL"
    )).scalar_one()
    if jobs:
        raise RuntimeError("Governed log jobs exist; use a forward migration to preserve them.")
    op.execute('DROP TRIGGER IF EXISTS "log_evidence_snapshot_metadata_immutable"')
    op.execute('DROP TRIGGER IF EXISTS "execution_job_auth_document_immutable"')
    op.execute('DROP TRIGGER IF EXISTS "execution_result_provenance_scope_guard"')
    op.execute("PRAGMA defer_foreign_keys=ON")
    with op.batch_alter_table("execution_jobs", recreate="always") as batch:
        batch.drop_constraint("fk_job_log_evidence_snapshot_scope", type_="foreignkey")
        batch.drop_column("log_evidence_manifest_version")
        batch.drop_column("log_evidence_sha256")
        batch.drop_column("log_evidence_snapshot_id")
        batch.drop_column("log_ruleset_version")
        batch.drop_column("log_analysis_version")
        batch.drop_column("log_evidence_source_format")
    op.drop_index("ix_log_reservation_org", table_name="log_evidence_quota_reservations")
    op.drop_table("log_evidence_quota_reservations")
    op.drop_index("ix_log_snapshot_tenant", table_name="log_evidence_snapshots")
    op.drop_table("log_evidence_snapshots")
    with op.batch_alter_table("engagement_assets", recreate="always") as batch:
        batch.drop_constraint("ck_asset_type", type_="check")
        batch.create_check_constraint(
            "ck_asset_type", "asset_type IN ('domain','ip','cidr','url','repository')"
        )
    _restore_execution_triggers()
