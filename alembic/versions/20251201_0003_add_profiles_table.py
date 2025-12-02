"""add profiles table

Revision ID: 20251201_0003
Revises: 20251201_0002
Create Date: 2025-12-01 19:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20251201_0003"
down_revision = "20251201_0002"
branch_labels = None
depends_on = None

profile_type_enum = sa.Enum(
    "SERVER_TLS",
    "CLIENT_TLS",
    "INTERMEDIATE_CA",
    "ROOT_CA",
    "CUSTOM",
    name="profile_type_enum",
)


def upgrade() -> None:
    bind = op.get_bind()
    profile_type_enum.create(bind, checkfirst=True)

    op.create_table(
        "profiles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("profile_type", profile_type_enum, nullable=False, server_default="SERVER_TLS"),
        sa.Column("default_issuer_ca_id", sa.String(length=36), nullable=True),
        sa.Column("subject_template", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("key_algorithm", sa.String(length=16), nullable=False, server_default="RSA"),
        sa.Column("key_size", sa.Integer(), nullable=False, server_default="2048"),
        sa.Column("validity_days_default", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("validity_days_min", sa.Integer(), nullable=True),
        sa.Column("validity_days_max", sa.Integer(), nullable=True),
        sa.Column("usage_config_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("output_config_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("store_in_db_default", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("environment_tags_default", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("owner_default", sa.String(length=255), nullable=True),
        sa.Column("available_in_simple_mode", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["default_issuer_ca_id"], ["certificate_authorities.id"], ondelete="SET NULL"),
    )


def downgrade() -> None:
    op.drop_table("profiles")
    bind = op.get_bind()
    profile_type_enum.drop(bind, checkfirst=True)
