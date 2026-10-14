from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.models import CASourceTypeEnum, CAStatusEnum, CertificateAuthority


def test_root_ca_setup_flow_creates_record(client, db_session):
    response = client.get("/setup")
    assert response.status_code == 200

    response = client.post("/setup/step1", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/setup/step2"

    response = client.post("/setup/step2", data={"ca_source": "create"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/setup/root"

    form_data = {
        "name": "Test Root",
        "subject_cn": "Test Root",
        "subject_o": "Lab",
        "subject_ou": "",
        "subject_c": "US",
        "subject_st": "CA",
        "subject_l": "San Francisco",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_years": "5",
        "path_length": "1",
        "download_cert": "true",
        "master_passphrase": "",
    }
    summary = client.post("/setup/root", data=form_data)
    assert summary.status_code == 200
    payload = _extract_config_payload(summary.text)

    complete = client.post(
        "/setup/complete",
        data={"mode": "create", "config_payload": payload},
        follow_redirects=False,
    )
    assert complete.status_code == 303
    assert complete.headers["location"].startswith("/cas/")

    assert db_session.query(CertificateAuthority).count() == 1


def test_import_ca_flow_creates_record(client, db_session):
    cert_pem, key_pem = _generate_test_ca_pem()
    client.post("/setup/step1")
    client.post("/setup/step2", data={"ca_source": "import"})

    form_data = {
        "name": "Imported Root",
        "cert_pem": cert_pem,
        "key_pem": key_pem,
        "key_passphrase": "",
        "allow_intermediate_issuance": "true",
        "master_passphrase": "",
    }
    summary = client.post("/setup/import", data=form_data)
    assert summary.status_code == 200

    payload = _extract_config_payload(summary.text)
    complete = client.post(
        "/setup/complete",
        data={"mode": "import", "config_payload": payload},
        follow_redirects=False,
    )
    assert complete.status_code == 303

    ca = db_session.query(CertificateAuthority).first()
    assert ca is not None
    assert ca.source_type in {CASourceTypeEnum.INTERMEDIATE, CASourceTypeEnum.EXTERNAL_IMPORTED}


def test_setup_redirects_when_ca_exists(client, db_session):
    db_session.add(
        CertificateAuthority(
            name="Existing CA",
            source_type=CASourceTypeEnum.ROOT,
            subject_cn="Existing CA",
            subject_json={"CN": "Existing CA"},
            serial_number="abc",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=365),
            key_algorithm="RSA",
            key_size=2048,
            status=CAStatusEnum.ACTIVE,
            cert_pem="CERT",
        )
    )
    db_session.commit()

    response = client.get("/setup", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/cas"

    response = client.get("/cas", follow_redirects=False)
    assert response.status_code == 200


def test_cas_list_empty_state(client):
    response = client.get("/cas")
    assert response.status_code == 200
    assert (
        "No Certificate Authorities configured yet." in response.text
        or "No certificate authorities yet." in response.text
    )


def _extract_config_payload(html: str) -> str:
    match = re.search(r'name="config_payload" value="([^"]+)"', html)
    assert match, "config payload not found"
    return match.group(1)


def _generate_test_ca_pem() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Imported Root"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return cert_pem, key_pem
