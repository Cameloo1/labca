"""crls table

Revision ID: 20261014_0009
Revises: 20261014_0008
Create Date: 2026-10-14 15:00:00.000000

Stores the latest CRL per certificate authority. The table holds no key
material, so the downgrade simply drops it.
"""

import sqlalchemy as sa

from alembic import op

revision = "20261014_0009"
down_revision = "20261014_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "crls",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("ca_id", sa.String(length=36), nullable=False),
        sa.Column("crl_number", sa.Integer(), nullable=False),
        sa.Column("this_update", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_update", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_count", sa.Integer(), nullable=False),
        sa.Column("der", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.ForeignKeyConstraint(["ca_id"], ["certificate_authorities.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("ca_id", name="uq_crls_ca_id"),
    )


def downgrade() -> None:
    op.drop_table("crls")
