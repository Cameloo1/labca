from __future__ import annotations

import enum

from sqlalchemy import Boolean, Enum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class AllowKeyDownloadPolicy(str, enum.Enum):
    ALL = "ALL"
    LEAF_ONLY = "LEAF_ONLY"
    CA_DISABLED = "CA_DISABLED"
    NONE = "NONE"


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    app_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    default_key_algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="RSA")
    default_key_size: Mapped[int] = mapped_column(Integer, nullable=False, default=2048)
    default_validity_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    max_leaf_validity_days: Mapped[int] = mapped_column(Integer, nullable=False, default=825)
    allow_key_download_policy: Mapped[AllowKeyDownloadPolicy] = mapped_column(
        Enum(AllowKeyDownloadPolicy, name="allow_key_download_policy_enum"),
        nullable=False,
        default=AllowKeyDownloadPolicy.ALL,
    )
    require_login: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    key_storage_encryption_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allow_intermediate_issuance: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
