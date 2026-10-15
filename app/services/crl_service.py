"""Build, store, and refresh signed X.509 CRLs, one per certificate authority.

CRL numbers are read and incremented under a process-local lock. The deployment
runs a single replica, so a process-local lock is enough to keep numbers
monotonic. Running more than one replica would need a database-level lock.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.logging_config import logger
from app.models import Certificate, CertificateAuthority, CrlRecord
from app.services import keystore, revocation_service
from app.services.cert_issuance_service import load_ca_private_key
from app.services.pki_service import ca_has_key, load_ca_certificate

RFC5280_TO_REASON_FLAG: dict[str, Optional[x509.ReasonFlags]] = {
    "unspecified": None,
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "cACompromise": x509.ReasonFlags.ca_compromise,
    "affiliationChanged": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "privilegeWithdrawn": x509.ReasonFlags.privilege_withdrawn,
}

_regenerate_lock = threading.Lock()


class CrlUnavailableError(Exception):
    """The CA has no key in LabCA, or its key cannot be unsealed."""


def _as_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _revoked_at(certificate: Certificate) -> datetime:
    if certificate.revoked_at is None:
        raise ValueError("Certificate is not revoked.")
    return _as_aware(certificate.revoked_at)


def reason_code_for(certificate: Certificate) -> str:
    code = certificate.revocation_reason_code
    if code is not None and code in RFC5280_TO_REASON_FLAG:
        return code
    mapped = revocation_service.UI_REASON_TO_RFC5280.get(certificate.revocation_reason or "", "unspecified")
    return mapped if mapped in RFC5280_TO_REASON_FLAG else "unspecified"


def revoked_entries(
    db: Session, ca: CertificateAuthority, now: datetime, settings: Optional[Settings] = None
) -> list[Certificate]:
    settings = settings or get_settings()
    cutoff = _as_aware(now) - timedelta(hours=settings.CRL_RETENTION_AFTER_EXPIRY_HOURS)
    rows = db.scalars(select(Certificate).where(Certificate.ca_id == ca.id, Certificate.revoked_at.is_not(None))).all()
    kept = [row for row in rows if _as_aware(row.not_after) >= cutoff]
    kept.sort(key=lambda row: (_revoked_at(row), row.serial_number))
    return kept


def _signature_hash(key: object) -> hashes.SHA256 | hashes.SHA384 | hashes.SHA512:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name == "secp384r1":
            return hashes.SHA384()
        if key.curve.name == "secp521r1":
            return hashes.SHA512()
    return hashes.SHA256()


def _load_signing_key(ca: CertificateAuthority) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    try:
        key = load_ca_private_key(ca)
    except (ValueError, TypeError, keystore.KeystoreError) as exc:
        raise CrlUnavailableError("CA key is unavailable.") from exc
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise CrlUnavailableError("CA key is unavailable.")
    return key


def regenerate_crl(
    db: Session,
    ca: CertificateAuthority,
    *,
    now: Optional[datetime] = None,
    settings: Optional[Settings] = None,
) -> CrlRecord:
    settings = settings or get_settings()
    if not ca_has_key(ca):
        raise CrlUnavailableError("CA has no private key in LabCA.")
    key = _load_signing_key(ca)
    now = _as_aware(now) if now is not None else datetime.now(timezone.utc)
    ca_cert = load_ca_certificate(ca)

    with _regenerate_lock:
        existing = db.scalars(select(CrlRecord).where(CrlRecord.ca_id == ca.id)).first()
        number = existing.crl_number + 1 if existing is not None else 1

        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + timedelta(hours=settings.CRL_VALIDITY_HOURS))
            .add_extension(x509.CRLNumber(number), critical=False)
        )
        try:
            ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)
        except x509.ExtensionNotFound:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
        builder = builder.add_extension(aki, critical=False)

        count = 0
        for cert in revoked_entries(db, ca, now, settings):
            try:
                serial = int(cert.serial_number, 16)
            except ValueError:
                logger.warning("Skipping revoked certificate with a non-hex serial", extra={"certificate_id": cert.id})
                continue
            entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(_revoked_at(cert))
            flag = RFC5280_TO_REASON_FLAG[reason_code_for(cert)]
            if flag is not None:
                entry = entry.add_extension(x509.CRLReason(flag), critical=False)
            builder = builder.add_revoked_certificate(entry.build())
            count += 1

        crl = builder.sign(private_key=key, algorithm=_signature_hash(key))
        der = crl.public_bytes(serialization.Encoding.DER)
        next_update = crl.next_update_utc
        if next_update is None:  # the builder always sets nextUpdate; this guards the type only
            raise CrlUnavailableError("CRL could not be built.")

        if existing is None:
            existing = CrlRecord(ca_id=ca.id)
            db.add(existing)
        existing.crl_number = number
        existing.this_update = crl.last_update_utc
        existing.next_update = next_update
        existing.generated_at = now
        existing.revoked_count = count
        existing.der = der
        db.commit()
        db.refresh(existing)
        return existing


def _needs_regeneration(db: Session, ca: CertificateAuthority, record: CrlRecord, now: datetime) -> bool:
    this_update = _as_aware(record.this_update)
    next_update = _as_aware(record.next_update)
    if now >= this_update + (next_update - this_update) / 2:
        return True
    newest = db.scalars(
        select(Certificate.revoked_at)
        .where(Certificate.ca_id == ca.id, Certificate.revoked_at.is_not(None))
        .order_by(Certificate.revoked_at.desc())
        .limit(1)
    ).first()
    return newest is not None and _as_aware(newest) > _as_aware(record.generated_at)


def get_current_crl(
    db: Session,
    ca: CertificateAuthority,
    *,
    now: Optional[datetime] = None,
    settings: Optional[Settings] = None,
) -> CrlRecord:
    settings = settings or get_settings()
    now = _as_aware(now) if now is not None else datetime.now(timezone.utc)
    record = db.scalars(select(CrlRecord).where(CrlRecord.ca_id == ca.id)).first()
    if record is not None and not _needs_regeneration(db, ca, record, now):
        return record
    try:
        return regenerate_crl(db, ca, now=now, settings=settings)
    except CrlUnavailableError:
        if record is not None and now < _as_aware(record.next_update):
            logger.warning("Serving stored CRL because regeneration failed", extra={"ca_id": ca.id})
            return record
        raise


def on_certificate_revoked(certificate: Certificate, db: Session) -> None:
    if not certificate.ca_id:
        logger.debug("Revoked certificate has no CA; no CRL to update", extra={"certificate_id": certificate.id})
        return
    ca = db.get(CertificateAuthority, certificate.ca_id)
    if ca is None or not ca_has_key(ca):
        logger.debug("No CA key held for revoked certificate; skipping CRL", extra={"certificate_id": certificate.id})
        return
    regenerate_crl(db, ca)


revocation_service.register_post_revoke_hook(on_certificate_revoked)
