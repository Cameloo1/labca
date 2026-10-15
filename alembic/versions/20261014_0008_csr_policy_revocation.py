"""csr signing, token policy, api revocation metadata

Revision ID: 20261014_0008
Revises: 20261014_0007
Create Date: 2026-10-14 12:00:00.000000

Adds the per-token policy column, URI SAN storage, the issuing token id and the
RFC 5280 revocation reason code. The downgrade drops only this new metadata.
"""

import sqlalchemy as sa

from alembic import op

revision = "20261014_0008"
down_revision = "20261014_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("api_tokens") as batch:
        batch.add_column(sa.Column("policy_json", sa.JSON(), nullable=True))
    with op.batch_alter_table("certificates") as batch:
        batch.add_column(sa.Column("san_uris", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        batch.add_column(sa.Column("issued_by_token_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("revocation_reason_code", sa.String(length=32), nullable=True))
        batch.create_index("ix_certificates_issued_by_token_id", ["issued_by_token_id"])


def downgrade() -> None:
    with op.batch_alter_table("certificates") as batch:
        batch.drop_index("ix_certificates_issued_by_token_id")
        batch.drop_column("revocation_reason_code")
        batch.drop_column("issued_by_token_id")
        batch.drop_column("san_uris")
    with op.batch_alter_table("api_tokens") as batch:
        batch.drop_column("policy_json")
