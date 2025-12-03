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


def _seed_ca(db_session) -> CertificateAuthority:
    now = datetime.now(timezone.utc)
    ca = CertificateAuthority(
        name="Example Root",
        source_type=CASourceTypeEnum.ROOT,
        subject_cn="Example Root",
        subject_json={"CN": "Example Root"},
        serial_number="CA123",
        not_before=now,
        not_after=now + timedelta(days=365),
        key_algorithm="RSA",
        key_size=4096,
        status=CAStatusEnum.ACTIVE,
        cert_pem="-----BEGIN CERTIFICATE-----root-----END CERTIFICATE-----",
    )
    cert = Certificate(
        common_name="service.lab",
        san_dns=["service.lab"],
        san_ips=[],
        serial_number="CERT001",
        not_before=now,
        not_after=now + timedelta(days=90),
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        owner=None,
        stored_key_encrypted_pem=None,
        cert_pem="-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----",
        is_ephemeral=False,
        type=CertificateTypeEnum.LEAF,
        ca=ca,
    )
    db_session.add_all([ca, cert])
    db_session.commit()
    db_session.refresh(ca)
    return ca


def test_ca_list_renders_records(client, db_session):
    _seed_ca(db_session)

    response = client.get("/cas")
    assert response.status_code == 200
    assert "Example Root" in response.text


def test_ca_detail_and_download(client, db_session):
    ca = _seed_ca(db_session)
    ca_id = ca.id

    detail = client.get(f"/cas/{ca_id}")
    assert detail.status_code == 200
    assert "RSA" in detail.text

    download = client.get(f"/cas/{ca_id}/download-cert")
    assert download.status_code == 200
    assert "BEGIN CERTIFICATE" in download.text
