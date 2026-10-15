from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class CrlRecord(TimestampMixin, Base):
    """The latest CRL built for one CA. The CRL number only increases."""

    __tablename__ = "crls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ca_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("certificate_authorities.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    crl_number: Mapped[int] = mapped_column(Integer, nullable=False)
    this_update: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    next_update: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_count: Mapped[int] = mapped_column(Integer, nullable=False)
    der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<CrlRecord ca_id={self.ca_id} number={self.crl_number}>"
