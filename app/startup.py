"""Startup checks that run before the application accepts requests."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from app.config import Settings
from app.logging_config import logger
from app.security.admin_auth import admin_email_set
from app.services import keystore

_MIN_SECRET_KEY_LENGTH = 32
_DATA_DIR = "/data"


class StartupCheckError(RuntimeError):
    """The configuration is unsafe or incomplete; the process must not start."""


def _database_under_data(database_url: str) -> bool:
    """True when the URL is a SQLite file whose resolved path is /data or below."""
    try:
        url = make_url(database_url)
    except ArgumentError:
        return False
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return False
    data_dir = Path(_DATA_DIR).resolve()
    resolved = Path(url.database).resolve()
    return resolved == data_dir or data_dir in resolved.parents


def run_startup_checks(settings: Settings, keyring: Optional[keystore.KeyRing] = None) -> None:
    try:
        keyring = keyring or keystore.get_keyring()
    except keystore.KeyringConfigError as exc:
        raise StartupCheckError(f"Keyring configuration error: {exc}") from None

    secret_ok = settings.SECRET_KEY != "CHANGE_ME" and len(settings.SECRET_KEY) >= _MIN_SECRET_KEY_LENGTH
    https_ok = (settings.PUBLIC_BASE_URL or "").startswith("https://")
    if settings.ENV.lower() == "prod":
        problems: list[str] = []
        active = keyring.active_kek_id
        if not keyring.kek_ids:
            problems.append("no KEK is loaded")
        if active is None:
            problems.append("LABCA_ACTIVE_KEK_ID is not set")
        elif not keyring.has(active):
            problems.append(f"active KEK '{active}' is not loaded")
        if not secret_ok:
            problems.append(
                f"SECRET_KEY must not be CHANGE_ME and must be at least {_MIN_SECRET_KEY_LENGTH} characters"
            )
        if settings.ENABLE_API_DOCS:
            problems.append("ENABLE_API_DOCS must be false")
        if settings.ADMIN_AUTH_MODE == "none":
            problems.append("ADMIN_AUTH_MODE=none is not allowed in prod.")
        if not https_ok:
            problems.append("PUBLIC_BASE_URL must be set to an https:// origin")
        if not _database_under_data(settings.DATABASE_URL):
            problems.append("DATABASE_URL must be a SQLite file under /data")
        if settings.WORKLOAD_ISSUANCE_ENABLED:
            if not settings.WORKLOAD_TRUST_DOMAIN:
                problems.append("WORKLOAD_TRUST_DOMAIN is required when WORKLOAD_ISSUANCE_ENABLED is true")
            if not settings.WORKLOAD_ISSUER_CA_NAME:
                problems.append("WORKLOAD_ISSUER_CA_NAME is required when WORKLOAD_ISSUANCE_ENABLED is true")
        if problems:
            raise StartupCheckError(
                "Refusing to start with ENV=prod: unsafe configuration\n" + "\n".join(f"- {item}" for item in problems)
            )
    else:
        if not secret_ok:
            logger.warning("SECRET_KEY is the placeholder or too short; set a random value of 32 or more characters")
        if settings.ENABLE_API_DOCS:
            logger.warning("ENABLE_API_DOCS is true; set it to false outside local development")
        if not https_ok:
            logger.warning("PUBLIC_BASE_URL is not an https:// origin")

    if settings.ADMIN_AUTH_MODE == "cloudflare_access":
        missing: list[str] = []
        if not settings.CF_ACCESS_TEAM_DOMAIN:
            missing.append("CF_ACCESS_TEAM_DOMAIN")
        if not settings.CF_ACCESS_AUD:
            missing.append("CF_ACCESS_AUD")
        if not admin_email_set(settings):
            missing.append("ADMIN_EMAILS")
        if missing:
            raise StartupCheckError("ADMIN_AUTH_MODE=cloudflare_access requires: " + ", ".join(missing) + ".")

    logger.info(
        "Keyring loaded",
        extra={"kek_count": len(keyring.kek_ids), "active_kek_id": keyring.active_kek_id},
    )
