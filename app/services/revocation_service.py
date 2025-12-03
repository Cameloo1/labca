from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Certificate


def revoke_certificate(certificate: Certificate, reason: str | None, db: Session) -> Certificate:
    """Mark a certificate as revoked in the database."""
    certificate.revoked_at = datetime.now(timezone.utc)
    certificate.revocation_reason = reason
    certificate.status = certificate.compute_status()
    db.add(certificate)
    db.commit()
    db.refresh(certificate)
    return certificate
