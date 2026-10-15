"""seal legacy private keys

Revision ID: 20261014_0007
Revises: 20251201_0006
Create Date: 2026-10-14 09:00:00.000000

Converts every legacy ``enc::<base64>`` private key value (CA keys and stored
leaf keys) to a ``labca:v1`` envelope token under the active KEK. A database
with no legacy values upgrades without any KEK configured. If legacy values
exist and no active KEK is loaded, the upgrade fails before changing any row.

There is no downgrade: reversing the conversion would write private keys back
as plaintext base64. Restore a pre-upgrade backup instead.
"""

from alembic import op
from app.services.keystore import load_keyring
from app.services.keystore_migration import convert_legacy_values

revision = "20261014_0007"
down_revision = "20251201_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    convert_legacy_values(op.get_bind(), load_keyring())


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrade is not supported: it would write private keys back as plaintext base64. "
        "Restore a pre-upgrade backup instead."
    )
