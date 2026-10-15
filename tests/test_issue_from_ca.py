from __future__ import annotations

from datetime import timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.models import Certificate, CertificateAuthority
from app.schemas import RootCAConfig
from app.services.ca_service import create_root_ca


def _create_ca(db_session):
    config = RootCAConfig(
        name="Test Root",
        subject_cn="Test Root",
        validity_years=2,
        key_algorithm="RSA",
        key_size=2048,
    )
    ca = create_root_ca(config, db_session)
    db_session.commit()
    db_session.refresh(ca)
    return ca.id


def test_issue_page_loads(client, db_session):
    ca_id = _create_ca(db_session)
    response = client.get(f"/cas/{ca_id}/issue")
    assert response.status_code == 200
    assert "Test Root" in response.text


def test_issue_certificate_from_ca(client, db_session, csrf):
    ca_id = _create_ca(db_session)
    payload = {
        "common_name": "leaf.lab",
        "organization": "Lab",
        "organizational_unit": "",
        "country": "US",
        "state": "CA",
        "locality": "San Francisco",
        "dns_sans": "leaf.lab",
        "ip_sans": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "365",
        "usage_preset": "server_tls",
        "store_in_db": "true",
        "environment_tags": "dev",
        "owner": "qa",
    }
    response = client.post(f"/cas/{ca_id}/issue", data={**payload, **csrf(client)}, follow_redirects=False)
    assert response.status_code == 303
    cert_url = response.headers["location"]
    assert cert_url.startswith("/certificates/")

    detail = client.get(cert_url)
    assert detail.status_code == 200
    assert "leaf.lab" in detail.text

    cert = db_session.query(Certificate).first()
    assert cert is not None
    assert cert.ca_id == ca_id

    # Verify certificate issuer equals CA subject
    loaded = x509.load_pem_x509_certificate(cert.cert_pem.encode("utf-8"))
    issuer_cn = loaded.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert issuer_cn == "Test Root"

    # Verify not_after <= CA not_after
    ca = db_session.get(CertificateAuthority, ca_id)
    assert ca is not None
    # Ensure both datetimes are timezone-aware for comparison
    cert_not_after = loaded.not_valid_after_utc
    if cert_not_after.tzinfo is None:
        cert_not_after = cert_not_after.replace(tzinfo=timezone.utc)
    ca_not_after = ca.not_after
    if ca_not_after.tzinfo is None:
        ca_not_after = ca_not_after.replace(tzinfo=timezone.utc)
    assert cert_not_after <= ca_not_after


def test_issue_certificate_rejects_long_validity(client, db_session, csrf):
    ca_id = _create_ca(db_session)
    payload = {
        "common_name": "too-long.lab",
        "dns_sans": "",
        "ip_sans": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "800",
        "usage_preset": "server_tls",
        "store_in_db": "true",
        "environment_tags": "",
        "owner": "",
    }
    response = client.post(f"/cas/{ca_id}/issue", data={**payload, **csrf(client)})
    assert response.status_code == 400
    assert "exceeds issuer CA validity" in response.text
