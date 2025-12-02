"""add audit logs table

Revision ID: 20251201_0006
Revises: 20251201_0005
Create Date: 2025-12-02 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20251201_0006"
down_revision = "20251201_0005"
branch_labels = None
depends_on = None

actor_type_enum = sa.Enum("USER", "API_TOKEN", "SYSTEM", name="actor_type_enum")
audit_status_enum = sa.Enum("SUCCESS", "FAILURE", name="audit_status_enum")


def upgrade() -> None:
    bind = op.get_bind()
    actor_type_enum.create(bind, checkfirst=True)
    audit_status_enum.create(bind, checkfirst=True)

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("actor_type", actor_type_enum, nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("status", audit_status_enum, nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    bind = op.get_bind()
    actor_type_enum.drop(bind, checkfirst=True)
    audit_status_enum.drop(bind, checkfirst=True)
