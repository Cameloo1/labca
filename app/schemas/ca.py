from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


class RootCAConfig(BaseModel):
    name: str
    subject_cn: str
    subject_o: Optional[str] = None
    subject_ou: Optional[str] = None
    subject_c: Optional[str] = None
    subject_st: Optional[str] = None
    subject_l: Optional[str] = None
    key_algorithm: Literal["RSA", "ECDSA"] = "RSA"
    key_size: Optional[Literal[2048, 3072, 4096]] = 2048
    curve: Optional[Literal["P-256", "P-384", "P-521"]] = "P-256"
    hash_algorithm: Literal["SHA256", "SHA384", "SHA512"] = "SHA256"
    validity_years: int = Field(ge=1, le=25, default=5)
    path_length: Optional[int] = Field(default=None, ge=0)
    download_cert: bool = False
    master_passphrase: Optional[str] = None

    @model_validator(mode="after")
    def _validate_key_constraints(self) -> "RootCAConfig":
        if self.key_algorithm == "RSA" and self.key_size is None:
            raise ValueError("RSA key size is required.")
        if self.key_algorithm == "ECDSA" and self.curve is None:
            raise ValueError("ECDSA curve is required.")
        return self


class ImportCAConfig(BaseModel):
    name: str
    cert_pem: str
    key_pem: str
    key_passphrase: Optional[str] = None
    allow_intermediate_issuance: bool = False
    master_passphrase: Optional[str] = None
