from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models import Certificate, CertificateAuthority


def create_certificate_authority(db: Session, data: Dict[str, Any]) -> CertificateAuthority:
    """Persist a certificate authority record and return the instance."""
    ca = CertificateAuthority(**data)
    db.add(ca)
    db.commit()
    db.refresh(ca)
    return ca


def create_certificate(
    db: Session,
    data: Dict[str, Any],
    *,
    ca: Optional[CertificateAuthority] = None,
) -> Certificate:
    """Persist a certificate record linked to an optional CA."""
    if ca is not None:
        data.setdefault("ca_id", ca.id)
    certificate = Certificate(**data)
    db.add(certificate)
    db.commit()
    db.refresh(certificate)
    return certificate
