from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models import (
    CAStatusEnum,
    CASourceTypeEnum,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
)
from app.services.persistence import create_certificate, create_certificate_authority


def _time_range(days: int = 365) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    return now, now + timedelta(days=days)


def test_create_certificate_authority_and_certificate(db_session: Session) -> None:
    not_before, not_after = _time_range()
    ca_data = {
        "name": "LabCA Root",
        "source_type": CASourceTypeEnum.ROOT,
        "subject_cn": "LabCA Root",
        "subject_json": {"CN": "LabCA Root"},
        "serial_number": "ABC123",
        "not_before": not_before,
        "not_after": not_after,
        "key_algorithm": "RSA",
        "key_size": 4096,
        "status": CAStatusEnum.ACTIVE,
        "cert_pem": "-----BEGIN CERTIFICATE-----root-----END CERTIFICATE-----",
        "key_encrypted_pem": None,
    }

    ca = create_certificate_authority(db_session, ca_data)
    assert ca.id is not None
    assert ca.subject_json["CN"] == "LabCA Root"

    cert_data = {
        "type": CertificateTypeEnum.LEAF,
        "common_name": "app.lab.local",
        "san_dns": ["app.lab.local"],
        "san_ips": ["127.0.0.1"],
        "serial_number": "CERT123",
        "not_before": not_before,
        "not_after": not_after,
        "key_algorithm": "RSA",
        "key_size": 2048,
        "status": CertificateStatusEnum.ACTIVE,
        "environment_tags": ["dev"],
        "owner": "devops",
        "stored_key_encrypted_pem": None,
        "cert_pem": "-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----",
        "is_ephemeral": False,
    }

    certificate = create_certificate(db_session, cert_data, ca=ca)
    assert certificate.ca_id == ca.id

    persisted = db_session.get(CertificateAuthority, ca.id)
    assert persisted is not None
    assert persisted.certificates[0].common_name == "app.lab.local"


def test_relationships_and_defaults(db_session: Session) -> None:
    not_before, not_after = _time_range(30)
    parent = CertificateAuthority(
        name="Parent CA",
        source_type=CASourceTypeEnum.EXTERNAL_IMPORTED,
        subject_cn="Parent CA",
        subject_json={"CN": "Parent CA"},
        serial_number="PARENT001",
        not_before=not_before,
        not_after=not_after,
        key_algorithm="ECDSA",
        key_size=384,
        status=CAStatusEnum.ACTIVE,
        cert_pem="-----BEGIN CERTIFICATE-----parent-----END CERTIFICATE-----",
    )
    child = CertificateAuthority(
        name="Intermediate CA",
        source_type=CASourceTypeEnum.INTERMEDIATE,
        subject_cn="Intermediate",
        subject_json={"CN": "Intermediate"},
        serial_number="CHILD001",
        not_before=not_before,
        not_after=not_after,
        key_algorithm="RSA",
        key_size=2048,
        status=CAStatusEnum.DISABLED,
        cert_pem="-----BEGIN CERTIFICATE-----child-----END CERTIFICATE-----",
        parent=parent,
    )
    db_session.add_all([parent, child])
    db_session.commit()

    loaded_child = db_session.get(CertificateAuthority, child.id)
    assert loaded_child is not None
    assert loaded_child.parent_ca_id == parent.id

    cert = Certificate(
        common_name="intermediate.lab.local",
        san_dns=["intermediate.lab.local"],
        san_ips=[],
        serial_number="CERT002",
        not_before=not_before,
        not_after=not_after,
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.REVOKED,
        environment_tags=[],
        owner=None,
        stored_key_encrypted_pem=None,
        cert_pem="-----BEGIN-----END-----",
        is_ephemeral=True,
        type=CertificateTypeEnum.INTERMEDIATE,
        ca=child,
        revoked_at=not_after,
        revocation_reason="Key compromise",
    )
    db_session.add(cert)
    db_session.commit()

    reloaded_cert = db_session.get(Certificate, cert.id)
    assert reloaded_cert is not None
    assert reloaded_cert.ca_id == child.id
    assert reloaded_cert.revocation_reason == "Key compromise"
