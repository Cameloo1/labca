"""Startup checks that run before the application accepts requests."""

from __future__ import annotations

from typing import Optional

from app.config import Settings
from app.logging_config import logger
from app.security.admin_auth import admin_email_set
from app.services import keystore


class StartupCheckError(RuntimeError):
    """The configuration is unsafe or incomplete; the process must not start."""


def run_startup_checks(settings: Settings, keyring: Optional[keystore.KeyRing] = None) -> None:
    try:
        keyring = keyring or keystore.get_keyring()
    except keystore.KeyringConfigError as exc:
        raise StartupCheckError(f"Keyring configuration error: {exc}") from None

    if settings.ENV.lower() == "prod":
        problems: list[str] = []
        active = keyring.active_kek_id
        if not keyring.kek_ids:
            problems.append("no KEK is loaded")
        if active is None:
            problems.append("LABCA_ACTIVE_KEK_ID is not set")
        elif not keyring.has(active):
            problems.append(f"active KEK '{active}' is not loaded")
        if problems:
            raise StartupCheckError("Refusing to start with ENV=prod: " + "; ".join(problems))

    if settings.ENV.lower() == "prod" and settings.ADMIN_AUTH_MODE == "none":
        raise StartupCheckError("ADMIN_AUTH_MODE=none is not allowed in prod.")
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
