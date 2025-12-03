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


def _seed_certificates(db_session):
    now = datetime.now(timezone.utc)
    ca = CertificateAuthority(
        name="Integration Root",
        source_type=CASourceTypeEnum.ROOT,
        subject_cn="Integration Root",
        subject_json={"CN": "Integration Root"},
        serial_number="CA-SEED",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365),
        key_algorithm="RSA",
        key_size=4096,
        status=CAStatusEnum.ACTIVE,
        cert_pem="-----BEGIN CERTIFICATE-----root-----END CERTIFICATE-----",
    )

    certificates = [
        Certificate(
            ca=ca,
            type=CertificateTypeEnum.LEAF,
            common_name="active.lab",
            san_dns=["active.lab"],
            san_ips=[],
            serial_number="CERT-ACTIVE",
            not_before=now - timedelta(days=10),
            not_after=now + timedelta(days=120),
            key_algorithm="RSA",
            key_size=2048,
            status=CertificateStatusEnum.ACTIVE,
            environment_tags=["prod"],
            owner="app",
            stored_key_encrypted_pem=None,
            cert_pem="-----BEGIN CERTIFICATE-----active-----END CERTIFICATE-----",
            is_ephemeral=False,
        ),
        Certificate(
            ca=ca,
            type=CertificateTypeEnum.LEAF,
            common_name="soon.lab",
            san_dns=["soon.lab", "alias.soon.lab"],
            san_ips=[],
            serial_number="CERT-SOON",
            not_before=now - timedelta(days=5),
            not_after=now + timedelta(days=5),
            key_algorithm="RSA",
            key_size=2048,
            status=CertificateStatusEnum.ACTIVE,
            environment_tags=["dev"],
            owner="team",
            stored_key_encrypted_pem=None,
            cert_pem="-----BEGIN CERTIFICATE-----soon-----END CERTIFICATE-----",
            is_ephemeral=False,
        ),
        Certificate(
            ca=ca,
            type=CertificateTypeEnum.LEAF,
            common_name="expired.lab",
            san_dns=["expired.lab"],
            san_ips=[],
            serial_number="CERT-EXPIRED",
            not_before=now - timedelta(days=60),
            not_after=now - timedelta(days=1),
            key_algorithm="RSA",
            key_size=2048,
            status=CertificateStatusEnum.ACTIVE,
            environment_tags=[],
            owner=None,
            stored_key_encrypted_pem=None,
            cert_pem="-----BEGIN CERTIFICATE-----expired-----END CERTIFICATE-----",
            is_ephemeral=False,
        ),
        Certificate(
            ca=ca,
            type=CertificateTypeEnum.LEAF,
            common_name="revoked.lab",
            san_dns=["revoked.lab"],
            san_ips=[],
            serial_number="CERT-REVOKED",
            not_before=now - timedelta(days=15),
            not_after=now + timedelta(days=200),
            key_algorithm="RSA",
            key_size=2048,
            status=CertificateStatusEnum.ACTIVE,
            environment_tags=[],
            owner=None,
            stored_key_encrypted_pem=None,
            cert_pem="-----BEGIN CERTIFICATE-----revoked-----END CERTIFICATE-----",
            is_ephemeral=False,
            revoked_at=now - timedelta(days=1),
            revocation_reason="keyCompromise",
        ),
    ]

    db_session.add(ca)
    db_session.add_all(certificates)
    db_session.commit()


def test_certificates_list_shows_records(client, db_session):
    _seed_certificates(db_session)

    response = client.get("/certificates")
    assert response.status_code == 200
    assert "Issued Certificates" in response.text
    assert "active.lab" in response.text
    assert "revoked.lab" in response.text


def test_search_filter_matches_common_name(client, db_session):
    _seed_certificates(db_session)

    response = client.get("/certificates", params={"search": "soon"})
    assert response.status_code == 200
    assert "soon.lab" in response.text
    assert "active.lab" not in response.text


def test_status_filter_uses_computed_state(client, db_session):
    _seed_certificates(db_session)

    response = client.get("/certificates", params={"status": "EXPIRED"})
    assert response.status_code == 200
    assert "expired.lab" in response.text
    # Active certificates are filtered out
    assert "active.lab" not in response.text

    revoked = client.get("/certificates", params={"status": "REVOKED"})
    assert revoked.status_code == 200
    assert "revoked.lab" in revoked.text
    assert "expired.lab" not in revoked.text


def test_expiry_filter_limits_to_upcoming_window(client, db_session):
    _seed_certificates(db_session)

    response = client.get("/certificates", params={"expiry_filter": "7"})
    assert response.status_code == 200
    assert "soon.lab" in response.text
    assert "active.lab" not in response.text
    assert "expired.lab" not in response.text
