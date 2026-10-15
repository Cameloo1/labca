"""Helpers for the public PKI endpoints: CA certificates, chains, trust bundle, and CDP/AIA URLs."""

from __future__ import annotations

from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AuthorityInformationAccessOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.logging_config import logger
from app.models import CAStatusEnum, CertificateAuthority

PEM_CONTENT_TYPE = "application/x-pem-file"
DER_CERT_CONTENT_TYPE = "application/pkix-cert"
DER_CRL_CONTENT_TYPE = "application/pkix-crl"

MAX_CHAIN_DEPTH = 5


def ca_has_key(ca: CertificateAuthority) -> bool:
    return ca.key_encrypted_pem is not None and ca.key_encrypted_pem != ""


def load_ca_certificate(ca: CertificateAuthority) -> x509.Certificate:
    return x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))


def sha256_fingerprint_hex(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def get_keyed_ca(db: Session, ca_id: str) -> Optional[CertificateAuthority]:
    ca = db.get(CertificateAuthority, ca_id)
    if ca is None or not ca_has_key(ca):
        return None
    return ca


def resolve_workload_issuer(db: Session, settings: Optional[Settings] = None) -> Optional[CertificateAuthority]:
    settings = settings or get_settings()
    name = settings.WORKLOAD_ISSUER_CA_NAME
    if not name:
        return None
    rows = db.scalars(
        select(CertificateAuthority).where(
            CertificateAuthority.name == name,
            CertificateAuthority.status == CAStatusEnum.ACTIVE,
        )
    ).all()
    matches = [row for row in rows if ca_has_key(row)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        logger.error("Workload issuer CA name is ambiguous", extra={"ca_name": name, "matches": len(matches)})
    return None


def chain_certificates(ca: CertificateAuthority, db: Session) -> list[x509.Certificate]:
    certs = [load_ca_certificate(ca)]
    current = ca
    for _ in range(MAX_CHAIN_DEPTH):
        if is_self_signed(certs[-1]) or current.parent_ca_id is None:
            break
        parent = db.get(CertificateAuthority, current.parent_ca_id)
        if parent is None:
            break
        try:
            parent_cert = load_ca_certificate(parent)
        except ValueError:
            logger.warning("Parent CA certificate does not parse", extra={"ca_id": parent.id})
            break
        if is_self_signed(parent_cert):
            break
        certs.append(parent_cert)
        current = parent
    return certs


def trust_bundle_certificates(db: Session) -> list[x509.Certificate]:
    rows = db.scalars(
        select(CertificateAuthority)
        .where(CertificateAuthority.status == CAStatusEnum.ACTIVE)
        .order_by(CertificateAuthority.not_before, CertificateAuthority.id)
    ).all()
    seen: set[str] = set()
    certs: list[x509.Certificate] = []
    for row in rows:
        try:
            cert = load_ca_certificate(row)
        except ValueError:
            logger.warning("CA certificate does not parse", extra={"ca_id": row.id})
            continue
        if not is_self_signed(cert):
            continue
        fingerprint = sha256_fingerprint_hex(cert)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        certs.append(cert)
    return certs


def public_url(path: str, settings: Optional[Settings] = None) -> str:
    settings = settings or get_settings()
    base = settings.PUBLIC_BASE_URL
    return f"{base}{path}" if base else path


def ca_urls(ca_id: str, settings: Optional[Settings] = None) -> dict[str, str]:
    return {
        "ca_pem": public_url(f"/pki/cas/{ca_id}/ca.pem", settings),
        "ca_der": public_url(f"/pki/cas/{ca_id}/ca.der", settings),
        "chain_pem": public_url(f"/pki/cas/{ca_id}/chain.pem", settings),
        "crl_der": public_url(f"/pki/cas/{ca_id}/crl.der", settings),
        "crl_pem": public_url(f"/pki/cas/{ca_id}/crl.pem", settings),
    }


def distribution_extensions(ca_id: str, settings: Optional[Settings] = None) -> list[tuple[x509.ExtensionType, bool]]:
    settings = settings or get_settings()
    if not settings.PUBLIC_BASE_URL:
        return []
    crl_url = public_url(f"/pki/cas/{ca_id}/crl.der", settings)
    ca_url = public_url(f"/pki/cas/{ca_id}/ca.der", settings)
    cdp = x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )
    aia = x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(ca_url),
            )
        ]
    )
    return [(cdp, False), (aia, False)]
