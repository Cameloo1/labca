"""Tests for input validation and robustness (Task 21.3)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.models import (
    CASourceTypeEnum,
    CAStatusEnum,
    CertificateAuthority,
)
from app.services import keystore


def _create_test_ca(db_session) -> CertificateAuthority:
    """Create a test CA for certificate issuance."""
    now = datetime.now(timezone.utc)
    ca_id = str(uuid.uuid4())
    ca = CertificateAuthority(
        id=ca_id,
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
        key_encrypted_pem=keystore.seal_ca_key(ca_id, b"test-ca-key"),
    )
    db_session.add(ca)
    db_session.commit()
    db_session.refresh(ca)
    return ca


# ========== Quick Cert Input Validation Tests ==========


def test_quick_cert_extremely_long_cn(client, db_session, csrf):
    """Test that extremely long CN (1024 chars) is handled gracefully."""
    long_cn = "a" * 1024
    payload = {
        "common_name": long_cn,
        "validity_days": "90",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "hash_algorithm": "SHA256",
        "usage_preset": "server_tls",
        "output_pem_cert": "true",
        "output_pem_key": "true",
    }

    response = client.post("/quick-cert", data={**payload, **csrf(client)}, follow_redirects=False)
    # Should either succeed (if DB allows) or return validation error, but not crash
    assert response.status_code != 500  # Should not be 500
    if response.status_code == 400:
        # Validation error is acceptable
        assert "common name" in response.text.lower() or "too long" in response.text.lower()


def test_quick_cert_invalid_ip_san(client, db_session, csrf):
    """Test that invalid IP SAN (999.999.999.999) returns error, not 500."""
    payload = {
        "common_name": "test.example.com",
        "ip_sans": "999.999.999.999",
        "validity_days": "90",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "hash_algorithm": "SHA256",
        "usage_preset": "server_tls",
        "output_pem_cert": "true",
        "output_pem_key": "true",
    }

    response = client.post("/quick-cert", data={**payload, **csrf(client)}, follow_redirects=False)
    assert response.status_code != 500
    if response.status_code == 400:
        assert "invalid ip" in response.text.lower() or "ip address" in response.text.lower()


def test_quick_cert_invalid_oid_in_advanced_mode(client, db_session, csrf):
    """Test that invalid OID string in advanced mode returns validation error or is handled gracefully."""
    payload = {
        "common_name": "test.example.com",
        "validity_days": "90",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "hash_algorithm": "SHA256",
        "usage_preset": "server_tls",
        "output_pem_cert": "true",
        "output_pem_key": "true",
        "eku_custom_oids": "invalid-oid-string",  # Invalid OID format
    }

    response = client.post("/quick-cert?mode=advanced", data={**payload, **csrf(client)}, follow_redirects=False)
    # Should either return validation error (400) or handle gracefully (200), but not crash (500)
    assert response.status_code != 500
    if response.status_code == 400:
        assert "oid" in response.text.lower() or "invalid" in response.text.lower()


def test_quick_cert_very_long_validity(client, db_session, csrf):
    """Test that very long validity (100 years) is handled gracefully."""
    # 100 years = 36500 days (approximately)
    payload = {
        "common_name": "test.example.com",
        "validity_days": "36500",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "hash_algorithm": "SHA256",
        "usage_preset": "server_tls",
        "output_pem_cert": "true",
        "output_pem_key": "true",
    }

    response = client.post("/quick-cert", data={**payload, **csrf(client)}, follow_redirects=False)
    # Should either validate and normalize or return error, but not crash
    assert response.status_code != 500
    if response.status_code == 400:
        assert "validity" in response.text.lower() or "days" in response.text.lower()


# ========== CA Creation Input Validation Tests ==========


def test_ca_creation_empty_cn(client, db_session, csrf):
    """Test that CA creation with empty CN returns validation error or is handled gracefully."""
    payload = {
        "name": "Test CA",
        "subject_cn": "",  # Empty CN
        "key_algorithm": "RSA",
        "key_size": "4096",
        "hash_algorithm": "SHA256",
        "validity_years": "5",
        "path_length": "1",
    }

    response = client.post("/setup/root", data={**payload, **csrf(client)}, follow_redirects=False)
    # Should either return validation error (400) or handle gracefully, but not crash (500)
    assert response.status_code != 500
    # If it succeeds (200), it means validation happens later or CN is optional
    # If it fails (400), it should have an error message
    if response.status_code == 400:
        assert (
            "cn" in response.text.lower()
            or "common name" in response.text.lower()
            or "required" in response.text.lower()
        )


def test_ca_creation_very_long_validity(client, db_session, csrf):
    """Test that very long validity (100 years) is handled gracefully."""
    payload = {
        "name": "Test CA",
        "subject_cn": "Test CA",
        "key_algorithm": "RSA",
        "key_size": "4096",
        "hash_algorithm": "SHA256",
        "validity_years": "100",  # Very long validity
        "path_length": "1",
    }

    response = client.post("/setup/root", data={**payload, **csrf(client)}, follow_redirects=False)
    # Should either validate (if within limits) or return error, but not crash
    assert response.status_code != 500
    if response.status_code == 400:
        assert "validity" in response.text.lower() or "years" in response.text.lower()


# ========== API Input Validation Tests ==========


def test_api_unexpected_json_keys(client, db_session):
    """Test that API ignores unexpected JSON keys or returns 422, not 500."""
    # Create API token first
    from app.services.api_token_service import create_token

    token, raw_token = create_token(
        "test-token",
        {"issue": True, "read": True},
        None,
        db_session,
    )

    # Try to issue cert with unexpected keys
    payload = {
        "common_name": "test.example.com",
        "validity_days": 90,
        "key_algorithm": "RSA",
        "key_size": 2048,
        "unexpected_key_1": "should be ignored",
        "random_field": 12345,
        "malicious_input": "<script>alert('xss')</script>",
    }

    response = client.post(
        "/api/v1/certificates",
        json=payload,
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    # Should either succeed (ignoring extra keys) or return 422, but not 500
    assert response.status_code != 500
    if response.status_code == 422:
        # Validation error is acceptable
        pass
    elif response.status_code == 201:
        # Success is also acceptable if extra keys are ignored
        assert "certificate_id" in response.json()


def test_api_invalid_type_for_key_size(client, db_session):
    """Test that invalid type (e.g., key_size: "large") returns 422, not 500."""
    from app.services.api_token_service import create_token

    token, raw_token = create_token(
        "test-token",
        {"issue": True, "read": True},
        None,
        db_session,
    )

    # Try with invalid type for key_size
    payload = {
        "common_name": "test.example.com",
        "validity_days": 90,
        "key_algorithm": "RSA",
        "key_size": "large",  # Invalid: should be int
    }

    response = client.post(
        "/api/v1/certificates",
        json=payload,
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 422
    assert response.status_code != 500
    # Should have validation error details
    detail = response.json().get("detail", [])
    assert len(detail) > 0


def test_api_invalid_type_for_validity_days(client, db_session):
    """Test that invalid type for validity_days returns 422, not 500."""
    from app.services.api_token_service import create_token

    token, raw_token = create_token(
        "test-token",
        {"issue": True, "read": True},
        None,
        db_session,
    )

    payload = {
        "common_name": "test.example.com",
        "validity_days": "not-a-number",  # Invalid type
        "key_algorithm": "RSA",
        "key_size": 2048,
    }

    response = client.post(
        "/api/v1/certificates",
        json=payload,
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 422
    assert response.status_code != 500


def test_api_missing_required_fields(client, db_session):
    """Test that missing required fields return 422, not 500."""
    from app.services.api_token_service import create_token

    token, raw_token = create_token(
        "test-token",
        {"issue": True, "read": True},
        None,
        db_session,
    )

    # Missing common_name
    payload = {
        "validity_days": 90,
        "key_algorithm": "RSA",
        "key_size": 2048,
    }

    response = client.post(
        "/api/v1/certificates",
        json=payload,
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 422
    assert response.status_code != 500


def test_certificate_issuance_from_ca_invalid_cn(client, db_session, csrf):
    """Test that issuing cert from CA with invalid CN returns error, not 500."""
    ca = _create_test_ca(db_session)

    # Try with empty CN
    payload = {
        "common_name": "",  # Empty CN
        "validity_days": "365",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "hash_algorithm": "SHA256",
        "usage_preset": "server_tls",
        "store_in_db": "true",
    }

    response = client.post(f"/cas/{ca.id}/issue", data={**payload, **csrf(client)}, follow_redirects=False)
    assert response.status_code != 500
    if response.status_code == 400:
        assert "common name" in response.text.lower() or "required" in response.text.lower()


def test_certificate_issuance_from_ca_extreme_validity(client, db_session, csrf):
    """Test that extreme validity values are handled gracefully."""
    ca = _create_test_ca(db_session)

    # Try with very long validity
    payload = {
        "common_name": "test.example.com",
        "validity_days": "999999",  # Extreme value
        "key_algorithm": "RSA",
        "key_size": "2048",
        "hash_algorithm": "SHA256",
        "usage_preset": "server_tls",
        "store_in_db": "true",
    }

    response = client.post(f"/cas/{ca.id}/issue", data={**payload, **csrf(client)}, follow_redirects=False)
    # Should either validate (if within CA's validity) or return error, but not crash
    assert response.status_code != 500
    if response.status_code == 400:
        assert "validity" in response.text.lower() or "days" in response.text.lower()
