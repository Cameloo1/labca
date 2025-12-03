"""add app settings table

Revision ID: 20251201_0002
Revises: 20251201_0001
Create Date: 2025-12-01 18:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20251201_0002"
down_revision = "20251201_0001"
branch_labels = None
depends_on = None

allow_policy_enum = sa.Enum("ALL", "LEAF_ONLY", "CA_DISABLED", "NONE", name="allow_key_download_policy_enum")


def upgrade() -> None:
    bind = op.get_bind()
    allow_policy_enum.create(bind, checkfirst=True)

    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("app_name", sa.String(length=255), nullable=True),
        sa.Column("default_key_algorithm", sa.String(length=16), nullable=False, server_default="RSA"),
        sa.Column("default_key_size", sa.Integer(), nullable=False, server_default="2048"),
        sa.Column("default_validity_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("max_leaf_validity_days", sa.Integer(), nullable=False, server_default="825"),
        sa.Column("allow_key_download_policy", allow_policy_enum, nullable=False, server_default="ALL"),
        sa.Column("require_login", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("key_storage_encryption_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("allow_intermediate_issuance", sa.Boolean(), nullable=False, server_default=sa.true()),
    )

    op.bulk_insert(
        sa.table(
            "app_settings",
            sa.column("id", sa.Integer()),
            sa.column("app_name", sa.String()),
            sa.column("default_key_algorithm", sa.String()),
            sa.column("default_key_size", sa.Integer()),
            sa.column("default_validity_days", sa.Integer()),
            sa.column("max_leaf_validity_days", sa.Integer()),
            sa.column("allow_key_download_policy", sa.String()),
            sa.column("require_login", sa.Boolean()),
            sa.column("key_storage_encryption_enabled", sa.Boolean()),
            sa.column("allow_intermediate_issuance", sa.Boolean()),
        ),
        [
            {
                "id": 1,
                "app_name": "LabCA",
                "default_key_algorithm": "RSA",
                "default_key_size": 2048,
                "default_validity_days": 365,
                "max_leaf_validity_days": 825,
                "allow_key_download_policy": "ALL",
                "require_login": False,
                "key_storage_encryption_enabled": True,
                "allow_intermediate_issuance": True,
            }
        ],
    )


def downgrade() -> None:
    op.drop_table("app_settings")
    bind = op.get_bind()
    allow_policy_enum.drop(bind, checkfirst=True)
