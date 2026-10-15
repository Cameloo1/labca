"""workload identity on certificates

Revision ID: 20261014_0010
Revises: 20261014_0009
Create Date: 2026-10-14 18:00:00.000000

Adds the SPIFFE ID a certificate was issued to, so a workload can revoke only
its own certificates. The audit actor type enum is non-native and has no CHECK
constraint on SQLite, so the new WORKLOAD value needs no schema change.
"""

import sqlalchemy as sa

from alembic import op

revision = "20261014_0010"
down_revision = "20261014_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("certificates") as batch:
        batch.add_column(sa.Column("issued_to_spiffe_id", sa.String(length=2048), nullable=True))
        batch.create_index("ix_certificates_issued_to_spiffe_id", ["issued_to_spiffe_id"])


def downgrade() -> None:
    with op.batch_alter_table("certificates") as batch:
        batch.drop_index("ix_certificates_issued_to_spiffe_id")
        batch.drop_column("issued_to_spiffe_id")
