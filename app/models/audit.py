from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class ActorType(str, enum.Enum):
    USER = "USER"
    API_TOKEN = "API_TOKEN"
    SYSTEM = "SYSTEM"
    WORKLOAD = "WORKLOAD"


class AuditStatus(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    actor_type: Mapped[ActorType] = mapped_column(Enum(ActorType, name="actor_type_enum"), nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    status: Mapped[AuditStatus] = mapped_column(Enum(AuditStatus, name="audit_status_enum"), nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    details_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
