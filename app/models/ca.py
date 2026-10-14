from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin

if TYPE_CHECKING:  # pragma: no cover
    from .certificate import Certificate


class CASourceTypeEnum(str, enum.Enum):
    ROOT = "ROOT"
    INTERMEDIATE = "INTERMEDIATE"
    EXTERNAL_IMPORTED = "EXTERNAL_IMPORTED"


class CAStatusEnum(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    EXPIRED = "EXPIRED"


class CertificateAuthority(TimestampMixin, Base):
    __tablename__ = "certificate_authorities"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[CASourceTypeEnum] = mapped_column(
        Enum(CASourceTypeEnum, name="ca_source_type_enum"),
        nullable=False,
        default=CASourceTypeEnum.ROOT,
    )
    parent_ca_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("certificate_authorities.id", ondelete="SET NULL"),
        nullable=True,
    )
    subject_cn: Mapped[str] = mapped_column(String(255), nullable=False)
    subject_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    key_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    key_size: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[CAStatusEnum] = mapped_column(
        Enum(CAStatusEnum, name="ca_status_enum"),
        nullable=False,
        default=CAStatusEnum.ACTIVE,
    )
    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    key_encrypted_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    parent: Mapped[Optional["CertificateAuthority"]] = relationship(
        "CertificateAuthority",
        remote_side="CertificateAuthority.id",
        back_populates="children",
    )
    children: Mapped[List["CertificateAuthority"]] = relationship(
        "CertificateAuthority",
        back_populates="parent",
    )
    certificates: Mapped[List["Certificate"]] = relationship(
        "Certificate",
        back_populates="ca",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<CertificateAuthority id={self.id} name={self.name}>"
