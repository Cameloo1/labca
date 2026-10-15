"""Convert legacy ``enc::`` private key values to sealed envelope tokens."""

from __future__ import annotations

import base64
import binascii

import sqlalchemy
from sqlalchemy import text

from app.services.keystore import LEGACY_PREFIX, SEALED_COLUMNS, KeyRing, aad_for


def convert_legacy_values(connection: sqlalchemy.engine.Connection, keyring: KeyRing) -> dict[str, int]:
    # Table and column names come only from SEALED_COLUMNS, never from user input.
    found: dict[str, list[tuple[str, str]]] = {}
    total = 0
    # B608 is suppressed on the SQL lines: names are constants from SEALED_COLUMNS, values are bound parameters.
    for table, column in SEALED_COLUMNS:
        sql = f"SELECT id, {column} FROM {table} WHERE {column} LIKE 'enc::%'"  # nosec B608  # constant identifiers
        select = text(sql)
        rows = [(str(row[0]), str(row[1])) for row in connection.execute(select)]
        found[f"{table}.{column}"] = rows
        total += len(rows)

    counts = {f"{table}.{column}": 0 for table, column in SEALED_COLUMNS}
    if total == 0:
        return counts

    active = keyring.active_kek_id
    if active is None or not keyring.has(active):
        raise RuntimeError(
            f"{total} legacy enc:: private key values found but no active KEK is loaded. "
            "Configure LABCA_KEK_DIR (or LABCA_KEK_<ID> outside prod) and LABCA_ACTIVE_KEK_ID, "
            "then rerun 'alembic upgrade head'."
        )

    prepared: list[tuple[str, str, str, str]] = []
    for table, column in SEALED_COLUMNS:
        for row_id, value in found[f"{table}.{column}"]:
            try:
                plaintext = base64.b64decode(value[len(LEGACY_PREFIX) :], validate=True)
            except (binascii.Error, ValueError):
                raise RuntimeError(f"Legacy value in {table} row {row_id} is not valid base64.") from None
            token = keyring.seal(plaintext, aad_for(table, row_id, column))
            prepared.append((table, column, row_id, token))

    for table, column, row_id, token in prepared:
        sql = f"UPDATE {table} SET {column} = :v WHERE id = :id"  # nosec B608  # constant identifiers
        update = text(sql)
        connection.execute(update, {"v": token, "id": row_id})
        counts[f"{table}.{column}"] += 1
    return counts
