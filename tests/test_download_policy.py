"""Tests for key download policy enforcement (Task 21.2)."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from app.models import (
    AllowKeyDownloadPolicy,
    CAStatusEnum,
    CASourceTypeEnum,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
)
from app.models.settings import AppSettings
from app.services.settings_service import update_app_settings


def _create_test_ca(db_session) -> CertificateAuthority:
    """Create a test CA."""
    now = datetime.now(timezone.utc)
    ca = CertificateAuthority(
        name="Test Root CA",
        source_type=CASourceTypeEnum.ROOT,
        subject_cn="Test Root CA",
        subject_json={"CN": "Test Root CA"},
        serial_number="TEST-CA-ROOT",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=3650),
        key_algorithm="RSA",
        key_size=4096,
        status=CAStatusEnum.ACTIVE,
        cert_pem="-----BEGIN CERTIFICATE-----\nTEST-CA-CERT\n-----END CERTIFICATE-----",
        key_encrypted_pem="enc::" + base64.b64encode(b"test-ca-key").decode("utf-8"),
    )
    db_session.add(ca)
    db_session.commit()
    db_session.refresh(ca)
    return ca


def _create_test_certificate(
    db_session,
    ca: CertificateAuthority,
    cert_type: CertificateTypeEnum,
    common_name: str = "test.example.com",
) -> Certificate:
    """Create a test certificate with stored key."""
    now = datetime.now(timezone.utc)
    cert = Certificate(
        ca=ca,
        type=cert_type,
        common_name=common_name,
        san_dns=[common_name],
        san_ips=[],
        serial_number=f"TEST-{cert_type.value}-{common_name}",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        owner=None,
        stored_key_encrypted_pem="enc::" + base64.b64encode(b"test-private-key").decode("utf-8"),
        cert_pem="-----BEGIN CERTIFICATE-----\nTEST-CERT\n-----END CERTIFICATE-----",
        is_ephemeral=False,
    )
    db_session.add(cert)
    db_session.commit()
    db_session.refresh(cert)
    return cert


def test_policy_none_blocks_all_downloads(client, db_session):
    """Test that NONE policy blocks all key downloads."""
    # Set policy to NONE
    update_app_settings(
        db_session,
        {"allow_key_download_policy": AllowKeyDownloadPolicy.NONE},
    )

    ca = _create_test_ca(db_session)
    leaf_cert = _create_test_certificate(db_session, ca, CertificateTypeEnum.LEAF, "leaf.test.com")
    intermediate_cert = _create_test_certificate(
        db_session, ca, CertificateTypeEnum.INTERMEDIATE, "intermediate.test.com"
    )

    # Try to download leaf cert key - should be blocked
    response = client.get(f"/certificates/{leaf_cert.id}/download-key")
    assert response.status_code == 403
    assert "disabled by policy" in response.text

    # Try to download intermediate cert key - should be blocked
    response = client.get(f"/certificates/{intermediate_cert.id}/download-key")
    assert response.status_code == 403
    assert "disabled by policy" in response.text


def test_policy_leaf_only_allows_leaf_blocks_intermediate(client, db_session):
    """Test that LEAF_ONLY policy allows leaf certs but blocks intermediate."""
    # Set policy to LEAF_ONLY
    update_app_settings(
        db_session,
        {"allow_key_download_policy": AllowKeyDownloadPolicy.LEAF_ONLY},
    )

    ca = _create_test_ca(db_session)
    leaf_cert = _create_test_certificate(db_session, ca, CertificateTypeEnum.LEAF, "leaf.test.com")
    intermediate_cert = _create_test_certificate(
        db_session, ca, CertificateTypeEnum.INTERMEDIATE, "intermediate.test.com"
    )

    # Leaf cert key download should succeed
    response = client.get(f"/certificates/{leaf_cert.id}/download-key")
    assert response.status_code == 200
    # Response should contain the decoded key (test data is base64 encoded "test-private-key")
    assert len(response.text) > 0

    # Intermediate cert key download should be blocked
    response = client.get(f"/certificates/{intermediate_cert.id}/download-key")
    assert response.status_code == 403
    assert "disabled by policy" in response.text


def test_policy_ca_disabled_blocks_intermediate_allows_leaf(client, db_session):
    """Test that CA_DISABLED policy blocks intermediate certs but allows leaf."""
    # Set policy to CA_DISABLED
    update_app_settings(
        db_session,
        {"allow_key_download_policy": AllowKeyDownloadPolicy.CA_DISABLED},
    )

    ca = _create_test_ca(db_session)
    leaf_cert = _create_test_certificate(db_session, ca, CertificateTypeEnum.LEAF, "leaf.test.com")
    intermediate_cert = _create_test_certificate(
        db_session, ca, CertificateTypeEnum.INTERMEDIATE, "intermediate.test.com"
    )

    # Leaf cert key download should succeed
    response = client.get(f"/certificates/{leaf_cert.id}/download-key")
    assert response.status_code == 200
    # Response should contain the decoded key (test data is base64 encoded "test-private-key")
    assert len(response.text) > 0

    # Intermediate cert key download should be blocked
    response = client.get(f"/certificates/{intermediate_cert.id}/download-key")
    assert response.status_code == 403
    assert "disabled by policy" in response.text


def test_policy_all_allows_all_downloads(client, db_session):
    """Test that ALL policy allows all key downloads."""
    # Set policy to ALL
    update_app_settings(
        db_session,
        {"allow_key_download_policy": AllowKeyDownloadPolicy.ALL},
    )

    ca = _create_test_ca(db_session)
    leaf_cert = _create_test_certificate(db_session, ca, CertificateTypeEnum.LEAF, "leaf.test.com")
    intermediate_cert = _create_test_certificate(
        db_session, ca, CertificateTypeEnum.INTERMEDIATE, "intermediate.test.com"
    )

    # Both should succeed
    response = client.get(f"/certificates/{leaf_cert.id}/download-key")
    assert response.status_code == 200
    assert len(response.text) > 0

    response = client.get(f"/certificates/{intermediate_cert.id}/download-key")
    assert response.status_code == 200
    assert len(response.text) > 0


def test_policy_enforcement_via_api(client, db_session):
    """Test that API endpoints also enforce the download policy."""
    # Set policy to NONE
    update_app_settings(
        db_session,
        {"allow_key_download_policy": AllowKeyDownloadPolicy.NONE},
    )

    ca = _create_test_ca(db_session)
    leaf_cert = _create_test_certificate(db_session, ca, CertificateTypeEnum.LEAF, "leaf.test.com")

    # Create API token
    from app.services.api_token_service import create_token

    token, raw_token = create_token(
        "test-token",
        {"issue": True, "read": True},
        None,
        db_session,
    )

    # Try to get certificate with private key via API
    response = client.get(
        f"/api/v1/certificates/{leaf_cert.id}",
        params={"include_private_key": "true"},
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 403
    assert "disabled" in response.json()["detail"].lower()

    # Without private key should work
    response = client.get(
        f"/api/v1/certificates/{leaf_cert.id}",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 200
    assert response.json()["private_key_pem"] is None


def test_certificate_without_stored_key_returns_404(client, db_session):
    """Test that certificates without stored keys return 404, regardless of policy."""
    update_app_settings(
        db_session,
        {"allow_key_download_policy": AllowKeyDownloadPolicy.ALL},
    )

    ca = _create_test_ca(db_session)
    now = datetime.now(timezone.utc)
    cert = Certificate(
        ca=ca,
        type=CertificateTypeEnum.LEAF,
        common_name="no-key.test.com",
        san_dns=["no-key.test.com"],
        san_ips=[],
        serial_number="TEST-NO-KEY",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        owner=None,
        stored_key_encrypted_pem=None,  # No key stored
        cert_pem="-----BEGIN CERTIFICATE-----\nTEST-CERT\n-----END CERTIFICATE-----",
        is_ephemeral=False,
    )
    db_session.add(cert)
    db_session.commit()
    db_session.refresh(cert)

    response = client.get(f"/certificates/{cert.id}/download-key")
    assert response.status_code == 404
    # The error detail should be in the response (either JSON for API or HTML for UI)
    # Since this is a UI route, it returns HTML, but the HTTPException detail should be present
    # We just verify the status code is correct

