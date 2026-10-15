"""Operator command line: ``python -m app.cli kek status|rewrap``."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ActorType, AuditStatus, Certificate, CertificateAuthority
from app.services import keystore
from app.services.audit_service import log_action

# (table, column, ORM class); the column names match keystore.SEALED_COLUMNS.
_SEALED_MODELS: Tuple[Tuple[str, str, Any], ...] = (
    (keystore.CA_KEY_TABLE, keystore.CA_KEY_COLUMN, CertificateAuthority),
    (keystore.CERT_KEY_TABLE, keystore.CERT_KEY_COLUMN, Certificate),
)


def _emit(obj: Dict[str, Any]) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="LabCA operator commands.")
    groups = parser.add_subparsers(dest="group", required=True)
    kek = groups.add_parser("kek", help="Key encryption key management.")
    actions = kek.add_subparsers(dest="action", required=True)
    actions.add_parser("status", help="Show loaded KEKs and how many records each one protects.")
    rewrap = actions.add_parser("rewrap", help="Re-wrap every stored key under another KEK.")
    rewrap.add_argument("--to", required=True, dest="to_kek_id", help="Target KEK id.")
    rewrap.add_argument("--dry-run", action="store_true", help="Compute the result without saving it.")
    return parser


def _sealed_rows(db: Session) -> List[Tuple[str, str, Any, str]]:
    """Return (table, column, row, value) for every non-null sealed value."""
    found: List[Tuple[str, str, Any, str]] = []
    for table, column, model in _SEALED_MODELS:
        for row in db.scalars(select(model)).all():
            value = getattr(row, column)
            if value is not None:
                found.append((table, column, row, value))
    return found


def _cmd_status(db: Session, keyring: keystore.KeyRing) -> int:
    totals: Counter[str] = Counter()
    by_column: Dict[str, Dict[str, int]] = {f"{table}.{column}": {} for table, column in keystore.SEALED_COLUMNS}
    legacy = 0
    malformed = 0
    for table, column, _row, value in _sealed_rows(db):
        try:
            kek_id = keystore.kek_id_of(value)
        except keystore.LegacyFormatError:
            legacy += 1
            continue
        except keystore.MalformedTokenError:
            malformed += 1
            continue
        totals[kek_id] += 1
        column_counts = by_column[f"{table}.{column}"]
        column_counts[kek_id] = column_counts.get(kek_id, 0) + 1
    _emit(
        {
            "active_kek_id": keyring.active_kek_id,
            "loaded_kek_ids": keyring.kek_ids,
            "records": dict(totals),
            "by_column": by_column,
            "legacy": legacy,
            "malformed": malformed,
        }
    )
    return 0


def _cmd_rewrap(db: Session, keyring: keystore.KeyRing, to_kek_id: str, dry_run: bool) -> int:
    if not keyring.has(to_kek_id):
        _error(f"KEK '{to_kek_id}' is not loaded")
        return 2

    rows = _sealed_rows(db)
    if any(value.startswith(keystore.LEGACY_PREFIX) for _t, _c, _r, value in rows):
        _error("legacy enc:: values present; run 'alembic upgrade head' first")
        return 1

    rewrapped = 0
    already_current = 0
    by_source: Counter[str] = Counter()
    for table, column, row, value in rows:
        row_id = row.id
        try:
            old_id = keystore.kek_id_of(value)
            if old_id == to_kek_id:
                keyring.rewrap(value, keystore.aad_for(table, row_id, column), to_kek_id)
                already_current += 1
                continue
            new_value = keyring.rewrap(value, keystore.aad_for(table, row_id, column), to_kek_id)
        except keystore.KeystoreError as exc:
            db.rollback()
            _error(f"rewrap failed for {table} {row_id}: {type(exc).__name__}")
            return 1
        setattr(row, column, new_value)
        rewrapped += 1
        by_source[old_id] += 1

    result = {
        "to_kek_id": to_kek_id,
        "dry_run": dry_run,
        "rewrapped": rewrapped,
        "already_current": already_current,
        "by_source_kek": dict(by_source),
    }
    if dry_run:
        db.rollback()
    else:
        # log_action commits, so the key updates and the audit row land in one transaction.
        log_action(
            db,
            actor_type=ActorType.SYSTEM,
            actor_id="cli",
            action="KEK_REWRAP",
            target_type="KEK",
            target_id=to_kek_id,
            status=AuditStatus.SUCCESS,
            details={
                "to_kek_id": to_kek_id,
                "rewrapped": rewrapped,
                "already_current": already_current,
                "by_source_kek": dict(by_source),
            },
        )
    _emit(result)
    return 0


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    session_factory: Optional[Callable[[], Session]] = None,
    keyring: Optional[keystore.KeyRing] = None,
) -> int:
    args = _build_parser().parse_args(argv)

    if session_factory is None:
        from app.db import SessionLocal

        session_factory = SessionLocal
    if keyring is None:
        try:
            keyring = keystore.get_keyring()
        except keystore.KeystoreError as exc:
            _error(str(exc))
            return 1

    db = session_factory()
    try:
        if args.action == "status":
            return _cmd_status(db, keyring)
        return _cmd_rewrap(db, keyring, args.to_kek_id, args.dry_run)
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
