"""create ca and certificate tables

Revision ID: 20251201_0001
Revises:
Create Date: 2025-12-01 15:30:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20251201_0001"
down_revision = None
branch_labels = None
depends_on = None

ca_source_enum = sa.Enum("ROOT", "INTERMEDIATE", "EXTERNAL_IMPORTED", name="ca_source_type_enum")
ca_status_enum = sa.Enum("ACTIVE", "DISABLED", "EXPIRED", name="ca_status_enum")
cert_status_enum = sa.Enum("ACTIVE", "EXPIRED", "REVOKED", name="certificate_status_enum")
cert_type_enum = sa.Enum("LEAF", "INTERMEDIATE", name="certificate_type_enum")


def upgrade() -> None:
    bind = op.get_bind()
    ca_source_enum.create(bind, checkfirst=True)
    ca_status_enum.create(bind, checkfirst=True)
    cert_status_enum.create(bind, checkfirst=True)
    cert_type_enum.create(bind, checkfirst=True)

    op.create_table(
        "certificate_authorities",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("source_type", ca_source_enum, nullable=False, server_default="ROOT"),
        sa.Column("parent_ca_id", sa.String(length=36), nullable=True),
        sa.Column("subject_cn", sa.String(length=255), nullable=False),
        sa.Column("subject_json", sa.JSON(), nullable=False),
        sa.Column("serial_number", sa.String(length=128), nullable=False, unique=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("key_algorithm", sa.String(length=32), nullable=False),
        sa.Column("key_size", sa.Integer(), nullable=False),
        sa.Column("status", ca_status_enum, nullable=False, server_default="ACTIVE"),
        sa.Column("cert_pem", sa.Text(), nullable=False),
        sa.Column("key_encrypted_pem", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["parent_ca_id"], ["certificate_authorities.id"], ondelete="SET NULL"),
    )

    op.create_table(
        "certificates",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("ca_id", sa.String(length=36), nullable=True),
        sa.Column("type", cert_type_enum, nullable=False, server_default="LEAF"),
        sa.Column("common_name", sa.String(length=255), nullable=False),
        sa.Column("san_dns", sa.JSON(), nullable=False),
        sa.Column("san_ips", sa.JSON(), nullable=False),
        sa.Column("serial_number", sa.String(length=128), nullable=False, unique=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("key_algorithm", sa.String(length=32), nullable=False),
        sa.Column("key_size", sa.Integer(), nullable=False),
        sa.Column("status", cert_status_enum, nullable=False, server_default="ACTIVE"),
        sa.Column("environment_tags", sa.JSON(), nullable=False),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("stored_key_encrypted_pem", sa.Text(), nullable=True),
        sa.Column("cert_pem", sa.Text(), nullable=False),
        sa.Column("is_ephemeral", sa.Boolean(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["ca_id"], ["certificate_authorities.id"], ondelete="SET NULL"),
    )


def downgrade() -> None:
    op.drop_table("certificates")
    op.drop_table("certificate_authorities")

    bind = op.get_bind()
    cert_type_enum.drop(bind, checkfirst=True)
    cert_status_enum.drop(bind, checkfirst=True)
    ca_status_enum.drop(bind, checkfirst=True)
    ca_source_enum.drop(bind, checkfirst=True)
