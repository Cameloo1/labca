from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

UsagePreset = Literal["server_tls", "client_tls", "advanced"]


class SimpleCertConfig(BaseModel):
    mode: Literal["simple"] = "simple"
    common_name: str
    dns_sans: list[str] = Field(default_factory=list)
    ip_sans: list[str] = Field(default_factory=list)
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None
    key_algorithm: Literal["RSA", "ECDSA"]
    key_size: Optional[Literal[2048, 3072, 4096]] = None
    curve: Optional[Literal["P-256", "P-384", "P-521"]] = None
    hash_algorithm: Literal["SHA256", "SHA384", "SHA512"]
    validity_days: int
    usage_preset: UsagePreset = "server_tls"
    output_pem_cert: bool = True
    output_pem_key: bool = True
    output_combined_pem: bool = False
    output_pfx: bool = False
    pfx_password: Optional[str] = None
    label: Optional[str] = None

    @model_validator(mode="after")
    def _validate_key_constraints(self) -> "SimpleCertConfig":
        if self.key_algorithm == "RSA" and self.key_size is None:
            raise ValueError("key_size is required when RSA is selected")
        if self.key_algorithm == "ECDSA" and self.curve is None:
            raise ValueError("curve is required when ECDSA is selected")
        return self


class CustomExtension(BaseModel):
    oid: str
    critical: bool = False
    value: str


class AdvancedCertConfig(SimpleCertConfig):
    mode: Literal["advanced"] = "advanced"  # type: ignore[assignment]  # subclass swaps the mode tag on purpose
    is_ca: bool = False
    path_length: Optional[int] = None
    key_usage_digital_signature: bool = True
    key_usage_non_repudiation: bool = False
    key_usage_key_encipherment: bool = True
    key_usage_data_encipherment: bool = False
    key_usage_key_agreement: bool = False
    key_usage_key_cert_sign: bool = False
    key_usage_crl_sign: bool = False
    key_usage_encipher_only: bool = False
    key_usage_decipher_only: bool = False
    eku_server_auth: bool = True
    eku_client_auth: bool = False
    eku_code_signing: bool = False
    eku_email_protection: bool = False
    eku_time_stamping: bool = False
    eku_ocsp_signing: bool = False
    eku_custom_oids: list[str] = Field(default_factory=list)
    subject_key_identifier: Literal["auto", "omit"] = "auto"
    authority_key_identifier: Literal["match_subject", "omit"] = "match_subject"
    crl_distribution_points: list[str] = Field(default_factory=list)
    ocsp_urls: list[str] = Field(default_factory=list)
    custom_extensions: list[CustomExtension] = Field(default_factory=list)


class QuickCertRequest(BaseModel):
    mode: Literal["simple", "advanced"]


class GeneratedCertBundle(BaseModel):
    cert_pem: Optional[bytes] = None
    key_pem: Optional[bytes] = None
    combined_pem: Optional[bytes] = None
    pfx: Optional[bytes] = None
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    serial_number: int
    common_name: str
    dns_sans: list[str]
    ip_sans: list[str]
    key_algorithm: Literal["RSA", "ECDSA"]
    key_size: int
    usage_preset: UsagePreset
    mode: Literal["simple", "advanced"]
    is_ca: bool = False
    path_length: Optional[int] = None
    key_usage: dict[str, bool] = Field(default_factory=dict)
    extended_key_usage: list[str] = Field(default_factory=list)
    crl_distribution_points: list[str] = Field(default_factory=list)
    ocsp_urls: list[str] = Field(default_factory=list)
    custom_extension_oids: list[str] = Field(default_factory=list)

    model_config = ConfigDict(arbitrary_types_allowed=True)
