from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models import (
    CASourceTypeEnum,
    CAStatusEnum,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
)


def _seed_certificate(db_session):
    now = datetime.now(timezone.utc)
    ca = CertificateAuthority(
        name="Revoker Root",
        source_type=CASourceTypeEnum.ROOT,
        subject_cn="Revoker Root",
        subject_json={"CN": "Revoker Root"},
        serial_number="REV-CA",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365),
        key_algorithm="RSA",
        key_size=4096,
        status=CAStatusEnum.ACTIVE,
        cert_pem="-----BEGIN CERTIFICATE-----root-----END CERTIFICATE-----",
    )
    cert = Certificate(
        ca=ca,
        type=CertificateTypeEnum.LEAF,
        common_name="revoke.me",
        san_dns=["revoke.me"],
        san_ips=[],
        serial_number="REV-CERT",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=["lab"],
        owner="ops",
        stored_key_encrypted_pem=None,
        cert_pem="-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----",
        is_ephemeral=False,
    )
    db_session.add_all([ca, cert])
    db_session.commit()
    db_session.refresh(cert)
    return cert.id


def test_revoke_certificate_flow(client, db_session):
    cert_id = _seed_certificate(db_session)

    form_page = client.get(f"/certificates/{cert_id}/revoke")
    assert form_page.status_code == 200
    assert "Revocation reason" in form_page.text

    response = client.post(
        f"/certificates/{cert_id}/revoke",
        data={"reason_code": "key_compromise", "notes": "api key leaked"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    detail_url = response.headers["location"]
    detail = client.get(detail_url)
    assert detail.status_code == 200
    assert "Revoked at" in detail.text
    assert "Key compromise" in detail.text
    assert "api key leaked" in detail.text

    record = db_session.get(Certificate, cert_id)
    assert record is not None
    assert record.revoked_at is not None
    assert record.status == CertificateStatusEnum.REVOKED
    assert record.revocation_reason and "api key leaked" in record.revocation_reason

    listing = client.get("/certificates")
    assert listing.status_code == 200
    assert "Revoked" in listing.text
