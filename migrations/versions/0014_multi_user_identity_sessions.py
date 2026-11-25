"""Add database-backed user credentials, persistent sessions, lockouts, and invitations."""

import sqlalchemy as sa
from alembic import op

revision = "0014_multi_user_identity_sessions"
down_revision = "0013_governed_chain_trace"
branch_labels = None
depends_on = None


def _recreate_users_status_check(check_expr: str) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        fk_enabled = bool(bind.execute(sa.text("PRAGMA foreign_keys")).scalar())
        with op.get_context().autocommit_block():
            if fk_enabled:
                bind.execute(sa.text("PRAGMA foreign_keys=OFF"))
            try:
                with op.batch_alter_table("users", recreate="always") as batch:
                    batch.drop_constraint("ck_users_status", type_="check")
                    batch.create_check_constraint("ck_users_status", check_expr)
            finally:
                if fk_enabled:
                    bind.execute(sa.text("PRAGMA foreign_keys=ON"))
        return
    with op.batch_alter_table("users", recreate="always") as batch:
        batch.drop_constraint("ck_users_status", type_="check")
        batch.create_check_constraint("ck_users_status", check_expr)


def upgrade() -> None:
    _recreate_users_status_check(
        "status IN ('active','suspended','archived','disabled','revoked','pending')"
    )

    op.create_table(
        "user_credentials",
        sa.Column("user_id", sa.String(36), primary_key=True),
        sa.Column("password_hash", sa.String(255)),
        sa.Column("totp_enabled", sa.Integer, nullable=False, server_default="0"),
        sa.Column("totp_secret", sa.String(64)),
        sa.Column("totp_last_counter", sa.Integer, nullable=False, server_default="-1"),
        sa.Column("totp_pending_secret", sa.String(64)),
        sa.Column("totp_enrollment_expires_at", sa.Integer),
        sa.Column("totp_verify_failed_at", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("migrated_operator_epoch", sa.String(64)),
        sa.Column("password_updated_at", sa.String(40)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.CheckConstraint("totp_enabled IN (0, 1)", name="ck_user_credentials_totp_enabled"),
    )

    op.create_table(
        "user_recovery_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("code_hash", sa.String(255), nullable=False),
        sa.Column("used_at", sa.String(40)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_user_recovery_codes_user", "user_recovery_codes", ["user_id"])

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("email_normalized", sa.String(254), nullable=False),
        sa.Column("csrf_token", sa.String(128), nullable=False),
        sa.Column("auth_epoch", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float, nullable=False),
        sa.Column("last_seen_at", sa.Float, nullable=False),
        sa.Column("expires_at", sa.Float, nullable=False),
        sa.Column("revoked_at", sa.Float),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("token_hash", name="uq_user_sessions_token_hash"),
    )
    op.create_index("ix_user_sessions_token_hash", "user_sessions", ["token_hash"], unique=True)
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])

    op.create_table(
        "organization_invitations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("email_normalized", sa.String(254), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("invited_by_user_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.Column("accepted_by_user_id", sa.String(36)),
        sa.Column("accepted_at", sa.String(40)),
        sa.Column("revoked_at", sa.String(40)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["accepted_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("token_hash", name="uq_org_invitations_token_hash"),
        sa.CheckConstraint(
            "role IN ('admin','member','auditor','viewer')", name="ck_org_invitation_role"
        ),
        sa.CheckConstraint(
            "status IN ('pending','accepted','revoked','expired')", name="ck_org_invitation_status"
        ),
    )
    op.create_index(
        "ix_org_invitations_token_hash", "organization_invitations", ["token_hash"], unique=True
    )
    op.create_index(
        "ix_org_invitations_org_email",
        "organization_invitations",
        ["organization_id", "email_normalized"],
    )
    op.create_index("ix_org_invitations_expires_at", "organization_invitations", ["expires_at"])

    op.create_table(
        "auth_lockouts",
        sa.Column("key_hash", sa.String(64), primary_key=True),
        sa.Column("failure_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("locked_until", sa.Float),
        sa.Column("updated_at", sa.Float, nullable=False),
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(
        sa.text("SELECT COUNT(*) FROM users WHERE status IN ('disabled','revoked','pending')")
    ).scalar_one():
        raise RuntimeError(
            "Cannot downgrade while disabled, revoked, or pending user accounts exist."
        )
    op.drop_table("auth_lockouts")
    op.drop_index("ix_org_invitations_expires_at", table_name="organization_invitations")
    op.drop_index("ix_org_invitations_org_email", table_name="organization_invitations")
    op.drop_index("ix_org_invitations_token_hash", table_name="organization_invitations")
    op.drop_table("organization_invitations")
    op.drop_index("ix_user_sessions_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_index("ix_user_sessions_token_hash", table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_index("ix_user_recovery_codes_user", table_name="user_recovery_codes")
    op.drop_table("user_recovery_codes")
    op.drop_table("user_credentials")

    _recreate_users_status_check("status IN ('active','suspended','archived')")
