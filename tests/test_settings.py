from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models import (
    AllowKeyDownloadPolicy,
    CASourceTypeEnum,
    CAStatusEnum,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
)
from app.models.settings import AppSettings


def _seed_certificate_with_key(db_session) -> str:
    now = datetime.now(timezone.utc)
    ca = CertificateAuthority(
        name="Settings Root",
        source_type=CASourceTypeEnum.ROOT,
        subject_cn="Settings Root",
        subject_json={"CN": "Settings Root"},
        serial_number="SET-CA",
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
        common_name="settings.leaf",
        san_dns=["settings.leaf"],
        san_ips=[],
        serial_number="SET-CERT",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=30),
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        owner=None,
        stored_key_encrypted_pem="enc::c2VjcmV0LWs=",  # base64("secret-k")
        cert_pem="-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----",
        is_ephemeral=False,
    )
    db_session.add_all([ca, cert])
    db_session.commit()
    db_session.refresh(cert)
    return cert.id


def test_settings_page_shows_defaults(client, db_session):
    response = client.get("/settings")
    assert response.status_code == 200
    assert "LabCA Settings" in response.text
    assert "Default validity" in response.text


def test_default_settings_created_if_missing(client, db_session):
    """Ensure default settings row is created if missing."""
    from app.services.settings_service import get_app_settings

    # Verify settings don't exist initially
    settings = db_session.get(AppSettings, 1)
    assert settings is None

    # Call get_app_settings which should create defaults
    settings = get_app_settings(db_session)
    assert settings is not None
    assert settings.app_name == "LabCA"
    assert settings.default_key_algorithm == "RSA"
    assert settings.default_key_size == 2048
    assert settings.default_validity_days == 365


def test_update_settings_and_key_download_policy(client, db_session, csrf):
    payload = {
        "app_name": "My Lab",
        "default_key_algorithm": "ECDSA",
        "default_key_size": "3072",
        "default_validity_days": "400",
        "max_leaf_validity_days": "500",
        "allow_key_download_policy": "NONE",
        "require_login": "true",
    }
    response = client.post("/settings", data={**payload, **csrf(client)}, follow_redirects=False)
    assert response.status_code == 303

    settings = db_session.get(AppSettings, 1)
    assert settings is not None
    assert settings.app_name == "My Lab"
    assert settings.default_key_algorithm == "ECDSA"
    assert settings.allow_key_download_policy == AllowKeyDownloadPolicy.NONE
    assert settings.require_login is True

    cert_id = _seed_certificate_with_key(db_session)
    download = client.get(f"/certificates/{cert_id}/download-key")
    assert download.status_code == 403
    assert "disabled by policy" in download.text
