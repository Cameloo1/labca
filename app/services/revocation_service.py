from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from sqlalchemy.orm import Session

from app.logging_config import logger
from app.models import Certificate

RFC5280_REASONS: tuple[str, ...] = (
    "unspecified",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "privilegeWithdrawn",
)

UI_REASON_TO_RFC5280: dict[str, str] = {
    "key_compromise": "keyCompromise",
    "ca_compromise": "cACompromise",
    "superseded": "superseded",
    "cessation_of_operation": "cessationOfOperation",
    "affiliation_changed": "affiliationChanged",
    "unspecified": "unspecified",
}

PostRevokeHook = Callable[[Certificate, Session], None]

_post_revoke_hooks: list[PostRevokeHook] = []


def register_post_revoke_hook(hook: PostRevokeHook) -> None:
    if hook not in _post_revoke_hooks:
        _post_revoke_hooks.append(hook)


def clear_post_revoke_hooks() -> None:
    _post_revoke_hooks.clear()


def snapshot_post_revoke_hooks() -> tuple[PostRevokeHook, ...]:
    return tuple(_post_revoke_hooks)


def restore_post_revoke_hooks(snapshot: tuple[PostRevokeHook, ...]) -> None:
    _post_revoke_hooks[:] = list(snapshot)


def revoke_certificate(
    certificate: Certificate,
    reason: str | None,
    db: Session,
    *,
    reason_code: str = "unspecified",
) -> Certificate:
    """Mark a certificate as revoked in the database, then run the post-revocation hooks."""
    if reason_code not in RFC5280_REASONS:
        raise ValueError("Unknown revocation reason code.")
    certificate.revoked_at = datetime.now(timezone.utc)
    certificate.revocation_reason = reason
    certificate.revocation_reason_code = reason_code
    certificate.status = certificate.compute_status()
    db.add(certificate)
    db.commit()
    db.refresh(certificate)
    for hook in list(_post_revoke_hooks):
        try:
            hook(certificate, db)
        except Exception:  # a hook must not undo a durable revocation; stale CRLs are regenerated on read
            logger.exception("Post-revocation hook failed", extra={"certificate_id": certificate.id})
    return certificate
