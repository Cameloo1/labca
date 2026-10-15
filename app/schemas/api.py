from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app.services.uri_san import MAX_URI_BYTES, validate_uri_san

_DNS_SUFFIX_RE = re.compile(r"^[a-z0-9*]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


class TokenPermissions(BaseModel):
    issue: bool = False
    read: bool = False
    revoke: bool = False


class TokenPolicy(BaseModel):
    allowed_dns_suffixes: list[str] = Field(default_factory=list)
    allowed_uri_prefixes: list[str] = Field(default_factory=list)
    max_validity_hours: int = Field(default=2160, ge=1, le=87600)
    revoke_any: bool = False

    @field_validator("allowed_dns_suffixes")
    @classmethod
    def _validate_dns_suffixes(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in values:
            suffix = raw.strip().lower().lstrip(".")
            if not suffix or not _DNS_SUFFIX_RE.match(suffix):
                raise ValueError(f"Invalid DNS suffix '{raw}'.")
            cleaned.append(suffix)
        return cleaned

    @field_validator("allowed_uri_prefixes")
    @classmethod
    def _validate_uri_prefixes(cls, values: list[str]) -> list[str]:
        for prefix in values:
            if not (prefix.startswith("spiffe://") or prefix.startswith("https://")):
                raise ValueError("URI prefixes must start with spiffe:// or https://.")
            # Without a "/" after the host, "spiffe://lab.example" would also match "spiffe://lab.example.evil/".
            if "/" not in prefix.split("://", 1)[1]:
                raise ValueError(
                    "URI prefixes must include the host followed by '/', for example spiffe://lab.example/."
                )
            if len(prefix.encode("utf-8")) > MAX_URI_BYTES:
                raise ValueError(f"URI prefixes must be at most {MAX_URI_BYTES} bytes.")
        return values


class TokenCreateRequest(BaseModel):
    name: str
    permissions: TokenPermissions = Field(default_factory=TokenPermissions)
    expires_at: Optional[datetime] = None
    policy: Optional[TokenPolicy] = None


class TokenCreateResponse(BaseModel):
    id: str
    name: str
    token_prefix: str
    token: str
    permissions: TokenPermissions
    expires_at: Optional[datetime]
    created_at: datetime
    policy: Optional[TokenPolicy] = None


class CertificateIssueRequest(BaseModel):
    issuer_ca_id: Optional[str] = None
    common_name: str
    dns_sans: list[str] = Field(default_factory=list)
    ip_sans: list[str] = Field(default_factory=list)
    uri_sans: list[str] = Field(default_factory=list)
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

    @field_validator("uri_sans")
    @classmethod
    def _validate_uri_sans(cls, values: list[str]) -> list[str]:
        return [validate_uri_san(value) for value in values]

    @model_validator(mode="after")
    def _validate_key_constraints(self) -> "CertificateIssueRequest":
        if self.key_algorithm == "RSA" and self.key_size is None:
            raise ValueError("key_size is required when key_algorithm is RSA.")
        if self.key_algorithm == "ECDSA" and self.curve is None:
            raise ValueError("curve is required when key_algorithm is ECDSA.")
        if self.uri_sans and self.issuer_ca_id is None:
            raise ValueError("uri_sans require issuer_ca_id.")
        return self


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


class CertificateSignRequest(BaseModel):
    issuer_ca_id: str
    csr_pem: str
    validity_hours: int = Field(ge=1, le=87600)
    usage_preset: Literal["server_tls", "client_tls", "mtls"] = "server_tls"


class CertificateSignResponse(BaseModel):
    certificate_id: str
    serial_hex: str
    not_before: datetime
    not_after: datetime
    certificate_pem: str
    chain_pem: str


class CertificateRevokeRequest(BaseModel):
    reason: Literal[
        "unspecified",
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "privilegeWithdrawn",
    ] = "unspecified"


class CertificateRevokeResponse(BaseModel):
    revoked: bool
    certificate_id: str
    serial_hex: str
    reason: str
    revoked_at: datetime
