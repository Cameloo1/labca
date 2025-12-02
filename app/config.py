from functools import lru_cache
from typing import Optional

try:
    from pydantic_settings import BaseSettings
except ImportError:  # pragma: no cover - fallback for environments without pydantic-settings
    from pydantic import BaseSettings  # type: ignore

from pydantic import Field


class Settings(BaseSettings):
    APP_NAME: str = Field("LabCA", description="Application display name")
    ENV: str = Field("dev", description="Environment name: dev/test/prod")
    DATABASE_URL: str = Field("sqlite:///./labca.db", description="SQLAlchemy database URL")
    SECRET_KEY: str = Field("CHANGE_ME", description="Application secret key")
    API_TOKEN_CREATION_SECRET: Optional[str] = Field(default=None, description="Required to mint API tokens")
    LOG_LEVEL: str = Field("INFO", description="Python logging level")
    ENABLE_API_DOCS: bool = Field(True, description="Enable Swagger/ReDoc endpoints")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
