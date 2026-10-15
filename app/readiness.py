"""Readiness checks behind GET /ready. Reasons are short codes; no exception text, paths, or ids."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from app.config import Settings
from app.services import pki_service
from app.services.keystore import KeyRing

_ALEMBIC_DIR = Path(__file__).resolve().parent.parent / "alembic"


@lru_cache(maxsize=1)
def _script_heads() -> frozenset[str]:
    config = Config()
    config.set_main_option("script_location", str(_ALEMBIC_DIR))
    return frozenset(ScriptDirectory.from_config(config).get_heads())


def _db_heads(db: Session) -> frozenset[str]:
    context = MigrationContext.configure(db.connection())
    return frozenset(context.get_current_heads())


def readiness_reasons(db: Session, settings: Settings, keyring: Optional[KeyRing]) -> list[str]:
    reasons: list[str] = []

    database_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # any failure means the database is not usable; the text must not leak
        database_ok = False
        reasons.append("database_unreachable")

    if database_ok:
        try:
            at_head = _db_heads(db) == _script_heads()
        except Exception:  # an unreadable version table counts as not migrated
            at_head = False
        if not at_head:
            reasons.append("migrations_not_at_head")

    if keyring is None or not keyring.kek_ids:
        reasons.append("keyring_empty")

    active = settings.LABCA_ACTIVE_KEK_ID
    if keyring is None or not active or not keyring.has(active):
        reasons.append("active_kek_missing")

    if database_ok and settings.WORKLOAD_ISSUANCE_ENABLED:
        try:
            issuer = pki_service.resolve_workload_issuer(db, settings)
        except Exception:  # a failing lookup means no usable issuer
            issuer = None
        if issuer is None:
            reasons.append("workload_issuer_missing")

    return reasons
