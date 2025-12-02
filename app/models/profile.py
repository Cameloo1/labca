from __future__ import annotations

import enum
import uuid
from typing import Optional

from sqlalchemy import JSON, Boolean, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin
from .ca import CertificateAuthority


class ProfileType(str, enum.Enum):
    SERVER_TLS = "SERVER_TLS"
    CLIENT_TLS = "CLIENT_TLS"
    INTERMEDIATE_CA = "INTERMEDIATE_CA"
    ROOT_CA = "ROOT_CA"
    CUSTOM = "CUSTOM"


class Profile(TimestampMixin, Base):
    __tablename__ = "profiles"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    profile_type: Mapped[ProfileType] = mapped_column(
        Enum(ProfileType, name="profile_type_enum"),
        nullable=False,
        default=ProfileType.SERVER_TLS,
    )
    default_issuer_ca_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("certificate_authorities.id", ondelete="SET NULL"),
        nullable=True,
    )
    subject_template: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    key_algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="RSA")
    key_size: Mapped[int] = mapped_column(Integer, nullable=False, default=2048)
    validity_days_default: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    validity_days_min: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    validity_days_max: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    usage_config_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    output_config_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    store_in_db_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    environment_tags_default: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    owner_default: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    available_in_simple_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    default_issuer: Mapped[Optional["CertificateAuthority"]] = relationship("CertificateAuthority")
