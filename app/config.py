from functools import lru_cache
from typing import Optional
from urllib.parse import urlsplit

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

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
