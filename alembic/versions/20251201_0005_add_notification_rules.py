"""add notification rules and logs

Revision ID: 20251201_0005
Revises: 20251201_0004
Create Date: 2025-12-02 09:00:00.000000
"""

import sqlalchemy as sa

from alembic import op

revision = "20251201_0005"
down_revision = "20251201_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("days_before_expiry", sa.Integer(), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("delivery_methods_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
    )

    op.create_table(
        "notification_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("certificate_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=False),
        sa.Column("delivery_method", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("message", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.ForeignKeyConstraint(["certificate_id"], ["certificates.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rule_id"], ["notification_rules.id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    op.drop_table("notification_logs")
    op.drop_table("notification_rules")
