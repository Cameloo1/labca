import re
from functools import lru_cache
from typing import Optional
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_allowlist(value: str) -> frozenset[tuple[str, str]]:
    """Parse comma-separated <namespace>/<serviceaccount> entries.

    Defined here so the settings validator can call it without importing the
    service layer; app.services.workload_service re-exports it.
    """
    entries: set[tuple[str, str]] = set()
    for raw in value.split(","):
        entry = raw.strip()
        if not entry:
            continue
        parts = entry.split("/")
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise ValueError("WORKLOAD_ALLOWLIST entries must look like <namespace>/<serviceaccount>.")
        entries.add((parts[0].strip(), parts[1].strip()))
    return frozenset(entries)


class Settings(BaseSettings):
    APP_NAME: str = Field(default="LabCA", description="Application display name")
    ENV: str = Field(default="dev", description="Environment name: dev/test/prod")
    DATABASE_URL: str = Field(default="sqlite:///./labca.db", description="SQLAlchemy database URL")
    SECRET_KEY: str = Field(default="CHANGE_ME", description="Application secret key")
    API_TOKEN_CREATION_SECRET: Optional[str] = Field(default=None, description="Required to mint API tokens")
    LOG_LEVEL: str = Field(default="INFO", description="Python logging level")
    ENABLE_API_DOCS: bool = Field(default=True, description="Enable Swagger/ReDoc endpoints")

    LABCA_KEK_DIR: Optional[str] = Field(default=None, description="Directory of KEK files (prod)")
    LABCA_ACTIVE_KEK_ID: Optional[str] = Field(default=None, description="KEK id used for new seals")

    PUBLIC_BASE_URL: Optional[str] = Field(default=None, description="Public origin used in CDP, AIA and /pki URLs")
    CRL_VALIDITY_HOURS: int = Field(default=24, ge=1, le=720, description="Hours between CRL thisUpdate and nextUpdate")
    CRL_RETENTION_AFTER_EXPIRY_HOURS: int = Field(
        default=1, ge=0, le=8760, description="Hours a revoked certificate stays on the CRL after it expires"
    )
    PKI_STATIC_DIR: Optional[str] = Field(default=None, description="Directory holding root-ca.pem and root-crl.der")
    WORKLOAD_ISSUER_CA_NAME: Optional[str] = Field(
        default=None, description="Name of the CA that issues workload certs"
    )

    WORKLOAD_ISSUANCE_ENABLED: bool = Field(default=False, description="Enable workload attestation routes")
    WORKLOAD_TRUST_DOMAIN: Optional[str] = Field(default=None, description="SPIFFE trust domain for workload IDs")
    WORKLOAD_TOKEN_AUDIENCE: str = Field(default="labca", min_length=1, description="Audience of workload tokens")
    WORKLOAD_ALLOWLIST: str = Field(default="", description="Comma-separated <namespace>/<serviceaccount> entries")
    WORKLOAD_CERT_TTL_MINUTES: int = Field(default=60, ge=5, le=1440, description="Workload certificate lifetime")
    WORKLOAD_SIGN_RATE_PER_HOUR: int = Field(
        default=30, ge=1, le=3600, description="Sign requests per identity per hour"
    )
    KUBE_SA_TOKEN_FILE: str = Field(
        default="/var/run/secrets/kubernetes.io/serviceaccount/token", description="LabCA's own ServiceAccount token"
    )
    KUBE_CA_FILE: str = Field(
        default="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", description="Kubernetes API CA bundle"
    )

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @field_validator("WORKLOAD_TRUST_DOMAIN", mode="before")
    @classmethod
    def _validate_trust_domain(cls, value: object) -> Optional[str]:
        if value is None or value == "":
            return None
        if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9._-]{1,255}", value):
            raise ValueError("WORKLOAD_TRUST_DOMAIN must match [a-z0-9._-]{1,255}.")
        return value

    @field_validator("WORKLOAD_ALLOWLIST", mode="after")
    @classmethod
    def _validate_allowlist(cls, value: str) -> str:
        parse_allowlist(value)
        return value

    @field_validator("PUBLIC_BASE_URL", mode="before")
    @classmethod
    def _validate_public_base_url(cls, value: object) -> Optional[str]:
        message = "PUBLIC_BASE_URL must be an http(s) origin with no path, query, or fragment."
        if value is None or value == "":
            return None
        if not isinstance(value, str):
            raise ValueError(message)
        try:
            parts = urlsplit(value)
        except ValueError:
            raise ValueError(message) from None
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(message)
        if parts.query or parts.fragment or parts.path not in ("", "/"):
            raise ValueError(message)
        return value.rstrip("/")


@lru_cache()
def get_settings() -> Settings:
    return Settings()
