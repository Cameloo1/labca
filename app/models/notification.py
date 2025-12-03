from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class NotificationRule(TimestampMixin, Base):
    __tablename__ = "notification_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    days_before_expiry: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    delivery_methods_json: Mapped[Dict[str, bool]] = mapped_column(JSON, nullable=False, default=dict)

    logs: Mapped[list["NotificationLog"]] = relationship(
        "NotificationLog",
        back_populates="rule",
        cascade="all, delete-orphan",
    )

    def active_methods(self) -> Dict[str, bool]:
        return self.delivery_methods_json or {}


class NotificationLog(Base):
    __tablename__ = "notification_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    certificate_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("certificates.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("notification_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    delivery_method: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    message: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    rule: Mapped[NotificationRule] = relationship("NotificationRule", back_populates="logs")
