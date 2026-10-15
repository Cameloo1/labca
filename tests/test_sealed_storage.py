"""End-to-end tests that private keys are sealed at rest and bound to their rows."""

from __future__ import annotations

import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.config import get_settings
from app.models import AllowKeyDownloadPolicy, Certificate, CertificateAuthority
from app.schemas import RootCAConfig
from app.services import keystore
from app.services.ca_service import create_root_ca
from app.services.quick_cert_service import save_quick_cert_to_db
from app.services.settings_service import update_app_settings

ISSUE_PAYLOAD = {
    "common_name": "sealed.lab",
    "organization": "Lab",
    "organizational_unit": "",
    "country": "US",
    "state": "CA",
    "locality": "SF",
    "dns_sans": "sealed.lab",
    "ip_sans": "",
    "key_algorithm": "RSA",
    "key_size": "2048",
    "curve": "P-256",
    "hash_algorithm": "SHA256",
    "validity_days": "30",
    "usage_preset": "server_tls",
    "store_in_db": "true",
    "environment_tags": "dev",
    "owner": "qa",
}


def _create_ca(db_session) -> CertificateAuthority:
    config = RootCAConfig(
        name="Sealed Root",
        subject_cn="Sealed Root",
        validity_years=2,
        key_algorithm="RSA",
        key_size=2048,
    )
    return create_root_ca(config, db_session)


def _issue(client, db_session, ca_id: str) -> Certificate:
    response = client.post(f"/cas/{ca_id}/issue", data=ISSUE_PAYLOAD, follow_redirects=False)
    assert response.status_code == 303
    cert_id = response.headers["location"].rsplit("/", 1)[-1].split("?")[0]
    certificate = db_session.get(Certificate, cert_id)
    assert certificate is not None
    return certificate


def _public_bytes(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_root_ca_key_is_sealed_with_row_aad(db_session):
    ca = _create_ca(db_session)

    value = ca.key_encrypted_pem
    assert value is not None and value.startswith("labca:v1:test-1:")
    pem = keystore.unseal_ca_key(ca.id, value)
    key = serialization.load_pem_private_key(pem, password=None)
    certificate = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
    assert _public_bytes(key.public_key()) == _public_bytes(certificate.public_key())
    with pytest.raises(keystore.IntegrityError):
        keystore.unseal_ca_key("other-id", value)


def test_issue_from_sealed_ca_and_download_key(client, db_session):
    update_app_settings(db_session, {"allow_key_download_policy": AllowKeyDownloadPolicy.ALL})
    ca = _create_ca(db_session)

    certificate = _issue(client, db_session, ca.id)

    stored = certificate.stored_key_encrypted_pem
    assert stored is not None and stored.startswith("labca:v1:test-1:")
    response = client.get(f"/certificates/{certificate.id}/download-key")
    assert response.status_code == 200
    key = serialization.load_pem_private_key(response.text.encode("utf-8"), password=None)
    loaded = x509.load_pem_x509_certificate(certificate.cert_pem.encode("utf-8"))
    assert _public_bytes(key.public_key()) == _public_bytes(loaded.public_key())


def test_issue_fails_cleanly_when_ca_key_cannot_be_unsealed(client, db_session):
    ca = _create_ca(db_session)
    other = _create_ca(db_session)
    ca.key_encrypted_pem = other.key_encrypted_pem  # sealed for a different row
    db_session.commit()

    response = client.post(f"/cas/{ca.id}/issue", data=ISSUE_PAYLOAD, follow_redirects=False)

    assert response.status_code == 400
    assert "could not be unsealed" in response.text
    assert "PRIVATE KEY" not in response.text


def test_quick_cert_key_is_sealed(client, db_session):
    payload = {
        "mode": "simple",
        "common_name": "quick-sealed.local",
        "dns_sans": "quick-sealed.local",
        "ip_sans": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "30",
        "usage_preset": "server_tls",
        "output_pem_cert": "true",
        "output_pem_key": "true",
        "store_in_labca": "true",
    }

    response = client.post("/quick-cert", data=payload, follow_redirects=False)

    assert response.status_code == 303
    record = db_session.query(Certificate).one()
    assert record.stored_key_encrypted_pem is not None
    assert record.stored_key_encrypted_pem.startswith("labca:v1:")
    pem = keystore.unseal_cert_key(record.id, record.stored_key_encrypted_pem)
    assert b"PRIVATE KEY" in pem


def test_quick_cert_without_key_stores_no_value(db_session):
    from app.schemas import SimpleCertConfig
    from app.services.crypto_service import generate_self_signed_cert_simple

    config = SimpleCertConfig(
        common_name="nokey.local",
        key_algorithm="RSA",
        key_size=2048,
        hash_algorithm="SHA256",
        validity_days=30,
    )
    bundle = generate_self_signed_cert_simple(config).model_copy(update={"key_pem": None})

    record = save_quick_cert_to_db(bundle, config, db_session, store_in_labca=True)

    assert record.stored_key_encrypted_pem is None


def test_swapped_key_columns_fail_closed(client, db_session):
    update_app_settings(db_session, {"allow_key_download_policy": AllowKeyDownloadPolicy.ALL})
    ca = _create_ca(db_session)
    first = _issue(client, db_session, ca.id)
    second_payload = {**ISSUE_PAYLOAD, "common_name": "second.lab", "dns_sans": "second.lab"}
    response = client.post(f"/cas/{ca.id}/issue", data=second_payload, follow_redirects=False)
    second = db_session.get(Certificate, response.headers["location"].rsplit("/", 1)[-1].split("?")[0])
    assert second is not None

    first.stored_key_encrypted_pem, second.stored_key_encrypted_pem = (
        second.stored_key_encrypted_pem,
        first.stored_key_encrypted_pem,
    )
    db_session.commit()

    result = client.get(f"/certificates/{first.id}/download-key")
    assert result.status_code == 500
    assert "Stored private key could not be decrypted." in result.text
    assert "PRIVATE KEY" not in result.text


def test_swapped_key_fails_closed_through_api(db_session, client):
    from app.services.api_token_service import create_token

    update_app_settings(db_session, {"allow_key_download_policy": AllowKeyDownloadPolicy.ALL})
    ca = _create_ca(db_session)
    first = _issue(client, db_session, ca.id)
    first.stored_key_encrypted_pem = keystore.seal_cert_key("different-row", b"stolen")
    db_session.commit()
    _token, raw_token = create_token("t", {"read": True}, None, db_session)

    result = client.get(
        f"/api/v1/certificates/{first.id}?include_private_key=true",
        headers={"Authorization": f"Bearer {raw_token}"},
    )

    assert result.status_code == 500
    assert result.json()["detail"] == "Stored private key could not be decrypted."


def test_setup_without_kek_returns_503(client, db_session, monkeypatch):
    client.post("/setup/step1")
    client.post("/setup/step2", data={"ca_source": "create"})
    form_data = {
        "name": "No Kek Root",
        "subject_cn": "No Kek Root",
        "subject_o": "Lab",
        "subject_ou": "",
        "subject_c": "US",
        "subject_st": "CA",
        "subject_l": "SF",
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
    match = re.search(r'name="config_payload" value="([^"]+)"', summary.text)
    assert match

    monkeypatch.delenv("LABCA_KEK_TEST_1")
    monkeypatch.delenv("LABCA_ACTIVE_KEK_ID")
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()

    response = client.post(
        "/setup/complete",
        data={"mode": "create", "config_payload": match.group(1)},
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert "Key storage is not configured" in response.text
    assert db_session.query(CertificateAuthority).count() == 0
