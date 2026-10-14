from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.models import ApiToken

TOKEN_PREFIX_LENGTH = 8


def create_token(
    name: str,
    permissions: Dict[str, bool],
    expires_at: Optional[datetime],
    db: Session,
) -> Tuple[ApiToken, str]:
    raw_token = _generate_raw_token()
    token = ApiToken(
        name=name,
        token_hash=_hash_token(raw_token),
        token_prefix=raw_token[:TOKEN_PREFIX_LENGTH],
        permissions_json=permissions,
        expires_at=expires_at,
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return token, raw_token


def validate_token(raw_token: str, db: Session) -> Optional[ApiToken]:
    if not raw_token:
        return None
    token_hash = _hash_token(raw_token)
    token = db.query(ApiToken).filter(ApiToken.token_hash == token_hash).one_or_none()
    if token is None:
        return None
    now = datetime.now(timezone.utc)
    if token.is_expired(now):
        return None
    token.last_used_at = now
    db.add(token)
    db.commit()
    db.refresh(token)
    return token


def list_tokens(db: Session) -> list[ApiToken]:
    return db.query(ApiToken).order_by(ApiToken.created_at.desc()).all()


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _generate_raw_token() -> str:
    return secrets.token_urlsafe(32)
