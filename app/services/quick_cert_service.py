from __future__ import annotations

import uuid
from typing import Union

from sqlalchemy.orm import Session

from app.models import Certificate, CertificateStatusEnum, CertificateTypeEnum
from app.schemas import AdvancedCertConfig, GeneratedCertBundle, SimpleCertConfig
from app.services import keystore
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
    issued_by_token_id: str | None = None,
) -> Certificate:
    """Persist a quick certificate issuance in the Certificate table."""
    if bundle.cert_pem is None:
        raise ValueError("Certificate PEM output is required to store quick certs in LabCA.")

    cert_id = str(uuid.uuid4())
    stored_key = keystore.seal_cert_key(cert_id, bundle.key_pem) if bundle.key_pem else None

    certificate = create_certificate(
        db,
        {
            "id": cert_id,
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
            "issued_by_token_id": issued_by_token_id,
        },
    )
    return certificate
