from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, validator


class IssueFromCAConfig(BaseModel):
    issuer_ca_id: str
    common_name: str
    dns_sans: list[str] = Field(default_factory=list)
    ip_sans: list[str] = Field(default_factory=list)
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    key_algorithm: Literal["RSA", "ECDSA"] = "RSA"
    key_size: Optional[Literal[2048, 3072, 4096]] = 2048
    curve: Optional[Literal["P-256", "P-384", "P-521"]] = "P-256"
    hash_algorithm: Literal["SHA256", "SHA384", "SHA512"] = "SHA256"
    validity_days: int = Field(ge=1, le=3650)
    is_ca: bool = False
    usage_preset: Literal["server_tls", "client_tls"] = "server_tls"
    store_in_db: bool = True
    environment_tags: list[str] = Field(default_factory=list)
    owner: Optional[str] = None
    enable_expiration_reminders: bool = False

    @validator("key_size", always=True)
    def validate_key_size(cls, value, values):
        if values.get("key_algorithm") == "RSA" and value is None:
            raise ValueError("key_size is required for RSA issuance.")
        return value

    @validator("curve", always=True)
    def validate_curve(cls, value, values):
        if values.get("key_algorithm") == "ECDSA" and value is None:
            raise ValueError("curve is required for ECDSA issuance.")
        return value
