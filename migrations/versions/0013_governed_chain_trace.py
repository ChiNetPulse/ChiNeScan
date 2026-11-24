"""Allow fixed-provider chain-address assets for governed trace lookups."""

import sqlalchemy as sa
from alembic import op

revision = "0013_governed_chain_trace"
down_revision = "0012_governed_malware_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("PRAGMA defer_foreign_keys=ON")
    with op.batch_alter_table("engagement_assets", recreate="always") as batch:
        batch.drop_constraint("ck_asset_type", type_="check")
        batch.create_check_constraint(
            "ck_asset_type",
            "asset_type IN ('domain','ip','cidr','url','repository','log_evidence',"
            "'malware_evidence','chain_address')",
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(
        sa.text("SELECT COUNT(*) FROM engagement_assets WHERE asset_type='chain_address'")
    ).scalar_one():
        raise RuntimeError("Cannot downgrade while governed chain-address assets exist.")
    for table_name in (
        "repository_asset_bindings",
        "log_evidence_snapshots",
        "malware_evidence_snapshots",
    ):
        if bind.execute(sa.text(f'SELECT COUNT(*) FROM "{table_name}"')).scalar_one():
            raise RuntimeError(
                "Governed evidence history exists; use a forward migration to preserve it."
            )
    op.execute("PRAGMA defer_foreign_keys=ON")
    with op.batch_alter_table("engagement_assets", recreate="always") as batch:
        batch.drop_constraint("ck_asset_type", type_="check")
        batch.create_check_constraint(
            "ck_asset_type",
            "asset_type IN ('domain','ip','cidr','url','repository','log_evidence',"
            "'malware_evidence')",
        )
