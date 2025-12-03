from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, validator


class TokenPermissions(BaseModel):
    issue: bool = False
    read: bool = False
    revoke: bool = False


class TokenCreateRequest(BaseModel):
    name: str
    permissions: TokenPermissions = Field(default_factory=TokenPermissions)
    expires_at: Optional[datetime] = None


class TokenCreateResponse(BaseModel):
    id: str
    name: str
    token_prefix: str
    token: str
    permissions: TokenPermissions
    expires_at: Optional[datetime]
    created_at: datetime


class CertificateIssueRequest(BaseModel):
    issuer_ca_id: Optional[str] = None
    common_name: str
    dns_sans: list[str] = Field(default_factory=list)
    ip_sans: list[str] = Field(default_factory=list)
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    key_algorithm: Literal["RSA", "ECDSA"] = "RSA"
    key_size: Optional[int] = 2048
    curve: Optional[Literal["P-256", "P-384", "P-521"]] = "P-256"
    hash_algorithm: Literal["SHA256", "SHA384", "SHA512"] = "SHA256"
    validity_days: int = Field(ge=1, le=3650, default=365)
    usage_preset: Literal["server_tls", "client_tls"] = "server_tls"
    is_ca: bool = False
    store_in_db: bool = True
    environment_tags: list[str] = Field(default_factory=list)
    owner: Optional[str] = None
    enable_expiration_reminders: bool = False
    return_private_key: bool = True

    @validator("key_size", always=True)
    def _require_key_size_for_rsa(cls, value, values):
        algorithm = values.get("key_algorithm")
        if algorithm == "RSA" and value is None:
            raise ValueError("key_size is required when key_algorithm is RSA.")
        return value

    @validator("curve", always=True)
    def _require_curve_for_ecdsa(cls, value, values):
        algorithm = values.get("key_algorithm")
        if algorithm == "ECDSA" and value is None:
            raise ValueError("curve is required when key_algorithm is ECDSA.")
        return value


class CertificateMetadata(BaseModel):
    id: str
    issuer_ca_id: Optional[str]
    type: str
    common_name: Optional[str]
    serial_number: Optional[str]
    not_before: datetime
    not_after: datetime
    owner: Optional[str]
    environment_tags: list[str]
    status: str
    download_allowed: bool


class CertificateResponse(BaseModel):
    certificate_id: str
    certificate_pem: str
    private_key_pem: Optional[str] = None
    metadata: CertificateMetadata
