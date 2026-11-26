"""Add engagement assets, immutable scope, authorization, and approvals."""

import sqlalchemy as sa
from alembic import op

revision = "0006_engagement_scope_policy"
down_revision = "0005_identity_organizations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "engagement_assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("client_id", sa.String(36)),
        sa.Column("engagement_id", sa.String(36)),
        sa.Column("asset_type", sa.String(20), nullable=False),
        sa.Column("target", sa.String(2048), nullable=False),
        sa.Column("description", sa.String(2000)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["client_id", "organization_id"],
            ["clients.id", "clients.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_engagement_asset_id_org"),
        sa.UniqueConstraint(
            "organization_id",
            "engagement_id",
            "asset_type",
            "target",
            name="uq_engagement_asset_target",
        ),
        sa.CheckConstraint("asset_type IN ('domain','ip','cidr','url')", name="ck_asset_type"),
        sa.CheckConstraint("status IN ('active','inactive')", name="ck_asset_status"),
    )
    op.create_index("ix_engagement_assets_org", "engagement_assets", ["organization_id"])
    op.create_index(
        "ix_assets_engagement", "engagement_assets", ["organization_id", "engagement_id"]
    )

    op.create_table(
        "scope_revisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("approved_by", sa.String(36)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("published_at", sa.String(40)),
        sa.Column("change_summary", sa.String(2000), nullable=False),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "approved_by"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("engagement_id", "revision", name="uq_scope_revision_number"),
        sa.UniqueConstraint("id", "organization_id", name="uq_scope_revision_id_org"),
        sa.CheckConstraint("revision > 0", name="ck_scope_revision_positive"),
        sa.CheckConstraint("status IN ('draft','published')", name="ck_scope_revision_status"),
        sa.CheckConstraint(
            "(status = 'draft' AND published_at IS NULL AND approved_by IS NULL) OR "
            "(status = 'published' AND published_at IS NOT NULL AND approved_by IS NOT NULL)",
            name="ck_scope_revision_publication_fields",
        ),
    )
    op.create_index(
        "ix_scope_revisions_engagement",
        "scope_revisions",
        ["organization_id", "engagement_id", "revision"],
    )

    op.create_table(
        "scope_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("scope_revision_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("asset_type_snapshot", sa.String(20), nullable=False),
        sa.Column("target_snapshot", sa.String(2048), nullable=False),
        sa.Column("effect", sa.String(10), nullable=False),
        sa.Column("match_mode", sa.String(20), nullable=False),
        sa.Column("techniques", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            ["scope_revision_id", "organization_id"],
            ["scope_revisions.id", "scope_revisions.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["engagement_assets.id", "engagement_assets.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("effect IN ('include','exclude')", name="ck_scope_rule_effect"),
        sa.CheckConstraint(
            "match_mode IN ('exact','subdomains','network','url_prefix')",
            name="ck_scope_rule_match_mode",
        ),
    )
    op.create_index(
        "ix_scope_rules_revision", "scope_rules", ["organization_id", "scope_revision_id"]
    )

    op.create_table(
        "authorization_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("client_id", sa.String(36)),
        sa.Column("scope_revision_id", sa.String(36), nullable=False),
        sa.Column("authorization_reference", sa.String(160), nullable=False),
        sa.Column("authorizing_party", sa.String(200), nullable=False),
        sa.Column("permitted_techniques", sa.JSON(), nullable=False),
        sa.Column("effective_at", sa.String(40), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("recorded_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["client_id", "organization_id"],
            ["clients.id", "clients.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scope_revision_id", "organization_id"],
            ["scope_revisions.id", "scope_revisions.organization_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "recorded_by"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("id", "organization_id", name="uq_authorization_id_org"),
        sa.UniqueConstraint(
            "engagement_id", "authorization_reference", name="uq_authorization_reference"
        ),
        sa.CheckConstraint("status IN ('active','revoked')", name="ck_authorization_status"),
        sa.CheckConstraint("expires_at > effective_at", name="ck_authorization_time_range"),
    )
    op.create_index(
        "ix_authorizations_engagement",
        "authorization_records",
        ["organization_id", "engagement_id"],
    )

    op.create_table(
        "authorization_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("authorization_id", sa.String(36), nullable=False),
        sa.Column("filename", sa.String(180), nullable=False),
        sa.Column("content_type", sa.String(120), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            ["authorization_id", "organization_id"],
            ["authorization_records.id", "authorization_records.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "created_by"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("authorization_id", name="uq_authorization_document_record"),
        sa.CheckConstraint(
            "size_bytes BETWEEN 1 AND 10485760", name="ck_authorization_document_size"
        ),
    )

    op.create_table(
        "approval_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("requester_user_id", sa.String(36), nullable=False),
        sa.Column("approver_user_id", sa.String(36)),
        sa.Column("asset_type", sa.String(20), nullable=False),
        sa.Column("target", sa.String(2048), nullable=False),
        sa.Column("technique", sa.String(80), nullable=False),
        sa.Column("action_class", sa.String(24), nullable=False),
        sa.Column("scope_revision_id", sa.String(36), nullable=False),
        sa.Column("authorization_id", sa.String(36), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("decision_reason", sa.String(500)),
        sa.Column("consumed_at", sa.String(40)),
        sa.Column("consumed_by", sa.String(36)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("decided_at", sa.String(40)),
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
            ["organization_id", "approver_user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "consumed_by"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
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
        sa.CheckConstraint(
            "approver_user_id IS NULL OR approver_user_id != requester_user_id",
            name="ck_approval_distinct_approver",
        ),
        sa.CheckConstraint(
            "decision IN ('pending','approved','denied','consumed','expired')",
            name="ck_approval_decision",
        ),
        sa.CheckConstraint(
            "action_class IN ('passive','controlled_active','sensitive')",
            name="ck_approval_action_class",
        ),
    )
    op.create_index(
        "ix_approval_requests_engagement",
        "approval_requests",
        ["organization_id", "engagement_id", "created_at"],
    )
    op.create_index("ix_approval_requests_pending", "approval_requests", ["decision", "expires_at"])

    op.create_table(
        "assessment_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("engagement_id", sa.String(36)),
        sa.Column("actor_user_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource_type", sa.String(40), nullable=False),
        sa.Column("resource_id", sa.String(36)),
        sa.Column("decision", sa.String(24)),
        sa.Column("reason_code", sa.String(80)),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["engagement_id", "organization_id"],
            ["engagements.id", "engagements.organization_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "actor_user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_assessment_audit_org_time",
        "assessment_audit_events",
        ["organization_id", "occurred_at"],
    )

    op.execute("""
        CREATE TRIGGER scope_revision_published_no_update
        BEFORE UPDATE ON scope_revisions WHEN OLD.status = 'published'
        BEGIN SELECT RAISE(ABORT, 'published scope revisions are immutable'); END
    """)
    op.execute("""
        CREATE TRIGGER scope_revision_published_no_delete
        BEFORE DELETE ON scope_revisions WHEN OLD.status = 'published'
        BEGIN SELECT RAISE(ABORT, 'published scope revisions are immutable'); END
    """)
    op.execute("""
        CREATE TRIGGER scope_rule_published_no_insert
        BEFORE INSERT ON scope_rules
        WHEN (SELECT status FROM scope_revisions WHERE id = NEW.scope_revision_id) = 'published'
        BEGIN SELECT RAISE(ABORT, 'published scope rules are immutable'); END
    """)
    op.execute("""
        CREATE TRIGGER scope_rule_published_no_update
        BEFORE UPDATE ON scope_rules
        WHEN (SELECT status FROM scope_revisions WHERE id = OLD.scope_revision_id) = 'published'
          OR (SELECT status FROM scope_revisions WHERE id = NEW.scope_revision_id) = 'published'
        BEGIN SELECT RAISE(ABORT, 'published scope rules are immutable'); END
    """)
    op.execute("""
        CREATE TRIGGER scope_rule_published_no_delete
        BEFORE DELETE ON scope_rules
        WHEN (SELECT status FROM scope_revisions WHERE id = OLD.scope_revision_id) = 'published'
        BEGIN SELECT RAISE(ABORT, 'published scope rules are immutable'); END
    """)
    op.execute("""
        CREATE TRIGGER assessment_audit_no_update
        BEFORE UPDATE ON assessment_audit_events
        BEGIN SELECT RAISE(ABORT, 'assessment audit is append-only'); END
    """)
    op.execute("""
        CREATE TRIGGER assessment_audit_no_delete
        BEFORE DELETE ON assessment_audit_events
        BEGIN SELECT RAISE(ABORT, 'assessment audit is append-only'); END
    """)


def downgrade() -> None:
    connection = op.get_bind()
    for table in (
        "assessment_audit_events",
        "approval_requests",
        "authorization_documents",
        "authorization_records",
        "scope_rules",
        "scope_revisions",
        "engagement_assets",
    ):
        if connection.execute(sa.text(f'SELECT COUNT(*) FROM "{table}"')).scalar_one():
            raise RuntimeError(
                "Phase 1C data exists; restore a verified backup or use a forward migration."
            )
    for trigger in (
        "assessment_audit_no_delete",
        "assessment_audit_no_update",
        "scope_rule_published_no_delete",
        "scope_rule_published_no_update",
        "scope_rule_published_no_insert",
        "scope_revision_published_no_delete",
        "scope_revision_published_no_update",
    ):
        op.execute(f'DROP TRIGGER IF EXISTS "{trigger}"')
    op.drop_index("ix_assessment_audit_org_time", table_name="assessment_audit_events")
    op.drop_table("assessment_audit_events")
    op.drop_index("ix_approval_requests_pending", table_name="approval_requests")
    op.drop_index("ix_approval_requests_engagement", table_name="approval_requests")
    op.drop_table("approval_requests")
    op.drop_table("authorization_documents")
    op.drop_index("ix_authorizations_engagement", table_name="authorization_records")
    op.drop_table("authorization_records")
    op.drop_index("ix_scope_rules_revision", table_name="scope_rules")
    op.drop_table("scope_rules")
    op.drop_index("ix_scope_revisions_engagement", table_name="scope_revisions")
    op.drop_table("scope_revisions")
    op.drop_index("ix_assets_engagement", table_name="engagement_assets")
    op.drop_index("ix_engagement_assets_org", table_name="engagement_assets")
    op.drop_table("engagement_assets")
