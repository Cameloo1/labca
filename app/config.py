from functools import lru_cache
from typing import Optional

from pydantic import Field
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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache()
def get_settings() -> Settings:
    return Settings()
