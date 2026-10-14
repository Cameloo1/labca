from __future__ import annotations

import base64
from typing import Union

from sqlalchemy.orm import Session

from app.models import Certificate, CertificateStatusEnum, CertificateTypeEnum
from app.schemas import AdvancedCertConfig, GeneratedCertBundle, SimpleCertConfig
from app.services.persistence import create_certificate

QuickCertConfig = Union[SimpleCertConfig, AdvancedCertConfig]


def save_quick_cert_to_db(
    bundle: GeneratedCertBundle,
    config: QuickCertConfig,
    db: Session,
    *,
    store_in_labca: bool,
    environment_tags: list[str] | None = None,
    owner: str | None = None,
) -> Certificate:
    """Persist a quick certificate issuance in the Certificate table."""
    if bundle.cert_pem is None:
        raise ValueError("Certificate PEM output is required to store quick certs in LabCA.")

    stored_key = _maybe_encrypt_key(bundle.key_pem)

    certificate = create_certificate(
        db,
        {
            "ca_id": None,
            "type": CertificateTypeEnum.INTERMEDIATE if bundle.is_ca else CertificateTypeEnum.LEAF,
            "common_name": bundle.common_name,
            "san_dns": bundle.dns_sans,
            "san_ips": bundle.ip_sans,
            "serial_number": f"{bundle.serial_number:x}",
            "not_before": bundle.not_before,
            "not_after": bundle.not_after,
            "key_algorithm": bundle.key_algorithm,
            "key_size": bundle.key_size,
            "status": CertificateStatusEnum.ACTIVE,
            "environment_tags": environment_tags if environment_tags is not None else ["quick-cert"],
            "owner": owner if owner is not None else (config.label or None),
            "stored_key_encrypted_pem": stored_key,
            "cert_pem": bundle.cert_pem.decode("utf-8"),
            "is_ephemeral": not store_in_labca,
        },
    )
    return certificate


def _maybe_encrypt_key(key_bytes: bytes | None) -> str | None:
    if not key_bytes:
        return None
    encoded = base64.b64encode(key_bytes).decode("utf-8")
    return f"enc::{encoded}"
