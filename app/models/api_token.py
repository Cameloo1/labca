from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class ApiToken(TimestampMixin, Base):
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    token_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    permissions_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    policy_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=None)

    def has_permission(self, permission: str) -> bool:
        permissions = self.permissions_json or {}
        return bool(permissions.get(permission, False))

    def is_expired(self, reference: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        reference = reference or datetime.now(timezone.utc)
        candidate = self.expires_at
        if candidate.tzinfo is None:
            candidate = candidate.replace(tzinfo=timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        return candidate < reference

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<ApiToken id={self.id} name={self.name}>"
