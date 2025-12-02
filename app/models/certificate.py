from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class CertificateStatusEnum(str, enum.Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class CertificateTypeEnum(str, enum.Enum):
    LEAF = "LEAF"
    INTERMEDIATE = "INTERMEDIATE"


class Certificate(TimestampMixin, Base):
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    ca_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("certificate_authorities.id", ondelete="SET NULL"),
        nullable=True,
    )
    type: Mapped[CertificateTypeEnum] = mapped_column(
        Enum(CertificateTypeEnum, name="certificate_type_enum"),
        nullable=False,
        default=CertificateTypeEnum.LEAF,
    )
    common_name: Mapped[str] = mapped_column(String(255), nullable=False)
    san_dns: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    san_ips: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    serial_number: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    key_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    key_size: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[CertificateStatusEnum] = mapped_column(
        Enum(CertificateStatusEnum, name="certificate_status_enum"),
        nullable=False,
        default=CertificateStatusEnum.ACTIVE,
    )
    environment_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    owner: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    stored_key_encrypted_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    is_ephemeral: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    ca: Mapped[Optional["CertificateAuthority"]] = relationship(
        "CertificateAuthority",
        back_populates="certificates",
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Certificate id={self.id} cn={self.common_name}>"

    def compute_status(self, reference: Optional[datetime] = None) -> CertificateStatusEnum:
        """Return a derived status based on revocation and expiry timestamps."""
        reference = reference or datetime.now(timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)

        if self.revoked_at is not None:
            return CertificateStatusEnum.REVOKED

        not_after = self.not_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)

        if not_after < reference:
            return CertificateStatusEnum.EXPIRED
        return CertificateStatusEnum.ACTIVE
