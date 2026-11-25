"""Add governed local repository assets, snapshots, and lead attestations."""

import sqlalchemy as sa
from alembic import op

revision = "0010_governed_repository_assets"
down_revision = "0009_execution_result_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Defer existing scope/job FKs while SQLite batch mode rebuilds the parent asset table.
    op.execute("PRAGMA defer_foreign_keys=ON")
    with op.batch_alter_table("engagement_assets", recreate="always") as batch:
        batch.drop_constraint("ck_asset_type", type_="check")
        batch.create_check_constraint(
            "ck_asset_type", "asset_type IN ('domain','ip','cidr','url','repository')"
        )
    op.add_column("engagements", sa.Column("closed_at", sa.String(40), nullable=True))
    op.create_table(
        "repository_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("manifest_version", sa.Integer(), nullable=False),
        sa.Column("scanner_version", sa.String(80), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("closed_at", sa.String(40)),
        sa.Column("delete_after", sa.String(40)),
        sa.Column("legal_hold", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hold_reason", sa.String(500)),
        sa.Column("deleted_at", sa.String(40)),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("id", "organization_id", name="uq_repository_snapshot_id_org"),
        sa.CheckConstraint(
            "size_bytes BETWEEN 0 AND 10737418240", name="ck_repository_snapshot_size"
        ),
        sa.CheckConstraint("manifest_version > 0", name="ck_repository_manifest_version"),
        sa.CheckConstraint(
            "status IN ('available','missing','corrupt','deleting','deleted')",
            name="ck_repository_snapshot_status",
        ),
        sa.CheckConstraint("legal_hold IN (0,1)", name="ck_repository_snapshot_hold"),
    )
    op.create_index(
        "ix_repository_snapshot_org_status", "repository_snapshots", ["organization_id", "status"]
    )
    op.create_table(
        "repository_asset_bindings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("project_registry_id", sa.String(80), nullable=False),
        sa.Column("source_kind", sa.String(40), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("display_label", sa.String(120), nullable=False),
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
            ["snapshot_id", "organization_id"],
            ["repository_snapshots.id", "repository_snapshots.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("asset_id", name="uq_repository_binding_asset"),
        sa.UniqueConstraint(
            "id", "organization_id", "engagement_id", "asset_id", name="uq_repository_binding_scope"
        ),
        sa.CheckConstraint(
            "source_kind = 'local_project_registry'", name="ck_repository_source_kind"
        ),
    )
    op.create_index(
        "ix_repository_binding_tenant",
        "repository_asset_bindings",
        ["organization_id", "engagement_id"],
    )
    op.create_table(
        "repository_attestations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("authorization_id", sa.String(36), nullable=False),
        sa.Column("scope_revision_id", sa.String(36), nullable=False),
        sa.Column("actor_user_id", sa.String(36), nullable=False),
        sa.Column("attestation_version", sa.String(40), nullable=False),
        sa.Column("attestation_text", sa.String(1000), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
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
            ["authorization_id", "organization_id"],
            ["authorization_records.id", "authorization_records.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scope_revision_id", "organization_id"],
            ["scope_revisions.id", "scope_revisions.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "actor_user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_repository_attestation_id_org"),
        sa.UniqueConstraint(
            "id",
            "organization_id",
            "engagement_id",
            "asset_id",
            "authorization_id",
            "scope_revision_id",
            name="uq_repository_attestation_binding",
        ),
    )
    op.create_index(
        "ix_repository_attestation_asset",
        "repository_attestations",
        ["organization_id", "engagement_id", "asset_id"],
    )
    op.create_table(
        "repository_quota_reservations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("reserved_bytes", sa.Integer(), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint("reserved_bytes >= 0", name="ck_repository_reservation_bytes"),
    )
    op.create_index(
        "ix_repository_reservation_org", "repository_quota_reservations", ["organization_id"]
    )
    for table in ("repository_asset_bindings", "repository_attestations"):
        op.execute(f"""CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table}
        BEGIN SELECT RAISE(
            ABORT, 'repository binding and attestation records are immutable'
        ); END""")
        op.execute(f"""CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table}
        BEGIN SELECT RAISE(
            ABORT, 'repository binding and attestation records are append-only'
        ); END""")
    op.execute("""CREATE TRIGGER repository_snapshot_metadata_immutable
        BEFORE UPDATE ON repository_snapshots
        WHEN NEW.sha256 != OLD.sha256 OR NEW.size_bytes != OLD.size_bytes
          OR NEW.manifest != OLD.manifest
          OR NEW.manifest_version != OLD.manifest_version
          OR NEW.scanner_version != OLD.scanner_version
          OR NEW.created_at != OLD.created_at
        BEGIN SELECT RAISE(ABORT, 'repository snapshot metadata is immutable'); END""")
    op.add_column("execution_jobs", sa.Column("policy_request_digest", sa.String(64)))
    op.add_column("execution_jobs", sa.Column("repository_binding_id", sa.String(36)))
    op.add_column("execution_jobs", sa.Column("repository_snapshot_id", sa.String(36)))
    op.add_column("execution_jobs", sa.Column("repository_snapshot_sha256", sa.String(64)))
    op.add_column("execution_jobs", sa.Column("repository_manifest_version", sa.Integer()))
    op.add_column("execution_jobs", sa.Column("repository_attestation_id", sa.String(36)))
    op.add_column("execution_jobs", sa.Column("repository_scanner_version", sa.String(80)))
    op.add_column("execution_jobs", sa.Column("repository_scan_bounds", sa.JSON()))
    op.add_column("execution_jobs", sa.Column("repository_attestation_version", sa.String(40)))
    op.add_column("execution_jobs", sa.Column("adapter_id", sa.String(80)))
    op.add_column("execution_jobs", sa.Column("adapter_version", sa.String(80)))
    op.add_column("execution_jobs", sa.Column("exclusion_policy_version", sa.String(80)))
    op.execute('DROP TRIGGER IF EXISTS "execution_result_provenance_scope_guard"')
    op.execute('DROP TRIGGER IF EXISTS "execution_job_auth_document_immutable"')
    op.execute("PRAGMA defer_foreign_keys=ON")
    with op.batch_alter_table("execution_jobs", recreate="always") as batch:
        batch.create_foreign_key(
            "fk_job_repository_binding_scope",
            "repository_asset_bindings",
            ["repository_binding_id", "organization_id", "engagement_id", "asset_id"],
            ["id", "organization_id", "engagement_id", "asset_id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_job_repository_snapshot_scope",
            "repository_snapshots",
            ["repository_snapshot_id", "organization_id"],
            ["id", "organization_id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_job_repository_attestation_scope",
            "repository_attestations",
            ["repository_attestation_id", "organization_id"],
            ["id", "organization_id"],
            ondelete="RESTRICT",
        )
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
    for table in (
        "repository_asset_bindings",
        "repository_attestations",
        "repository_snapshots",
        "repository_quota_reservations",
    ):
        if bind.execute(sa.text(f'SELECT COUNT(*) FROM "{table}"')).scalar_one():
            raise RuntimeError(
                "Repository snapshot history exists; use a forward migration to preserve it."
            )
    if bind.execute(
        sa.text("SELECT COUNT(*) FROM engagement_assets WHERE asset_type='repository'")
    ).scalar_one():
        raise RuntimeError("Repository assets exist; use a forward migration to preserve them.")
    op.execute("PRAGMA defer_foreign_keys=ON")
    op.execute('DROP TRIGGER IF EXISTS "execution_result_provenance_scope_guard"')
    op.execute('DROP TRIGGER IF EXISTS "execution_job_auth_document_immutable"')
    with op.batch_alter_table("execution_jobs", recreate="always") as batch:
        batch.drop_constraint("fk_job_repository_attestation_scope", type_="foreignkey")
        batch.drop_constraint("fk_job_repository_snapshot_scope", type_="foreignkey")
        batch.drop_constraint("fk_job_repository_binding_scope", type_="foreignkey")
        for column in (
            "exclusion_policy_version",
            "adapter_version",
            "adapter_id",
            "repository_attestation_version",
            "repository_scan_bounds",
            "repository_scanner_version",
            "repository_attestation_id",
            "repository_manifest_version",
            "repository_snapshot_sha256",
            "repository_snapshot_id",
            "repository_binding_id",
            "policy_request_digest",
        ):
            batch.drop_column(column)
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
    for trigger in (
        "repository_asset_bindings_no_update",
        "repository_asset_bindings_no_delete",
        "repository_attestations_no_update",
        "repository_attestations_no_delete",
        "repository_snapshot_metadata_immutable",
    ):
        op.execute(f'DROP TRIGGER IF EXISTS "{trigger}"')
    op.drop_index("ix_repository_reservation_org", table_name="repository_quota_reservations")
    op.drop_table("repository_quota_reservations")
    op.drop_index("ix_repository_attestation_asset", table_name="repository_attestations")
    op.drop_table("repository_attestations")
    op.drop_index("ix_repository_binding_tenant", table_name="repository_asset_bindings")
    op.drop_table("repository_asset_bindings")
    op.drop_index("ix_repository_snapshot_org_status", table_name="repository_snapshots")
    op.drop_table("repository_snapshots")
    op.drop_column("engagements", "closed_at")
    op.execute("PRAGMA defer_foreign_keys=ON")
    with op.batch_alter_table("engagement_assets", recreate="always") as batch:
        batch.drop_constraint("ck_asset_type", type_="check")
        batch.create_check_constraint("ck_asset_type", "asset_type IN ('domain','ip','cidr','url')")
