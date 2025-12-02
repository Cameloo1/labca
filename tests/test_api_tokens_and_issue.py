from __future__ import annotations
from unittest.mock import patch

from datetime import datetime, timedelta, timezone

import pytest

from app.models import Certificate
from app.schemas import RootCAConfig
from app.services.api_token_service import create_token
from app.services.ca_service import create_root_ca


# The API_TOKEN_CREATION_SECRET is already set by conftest.py settings_override fixture
# No additional fixture needed


def _create_ca(db_session):
    config = RootCAConfig(
        name="API Root",
        subject_cn="API Root",
        validity_years=3,
        key_algorithm="RSA",
        key_size=2048,
    )
    ca = create_root_ca(config, db_session)
    db_session.commit()
    db_session.refresh(ca)
    return ca.id


def _create_api_token(client, permissions: dict) -> str:
    response = client.post(
        "/api/v1/tokens",
        headers={"X-LabCA-Admin-Secret": "unit-secret"},  # Must match conftest.py settings_override
        json={
            "name": "pytest",
            "permissions": permissions,
        },
    )
    assert response.status_code == 201
    token_value = response.json()["token"]
    assert len(response.json()["token_prefix"]) == 8
    return token_value


def test_create_token_endpoint(client, db_session):
    token_value = _create_api_token(client, {"issue": True, "read": True, "revoke": False})
    assert len(token_value) > 30


def test_issue_certificate_with_ca_api(client, db_session):
    ca_id = _create_ca(db_session)
    token_value = _create_api_token(client, {"issue": True, "read": True})
    response = client.post(
        "/api/v1/certificates",
        headers={"Authorization": f"Bearer {token_value}"},
        json={
            "issuer_ca_id": ca_id,
            "common_name": "issued.api.lab",
            "dns_sans": ["issued.api.lab"],
            "ip_sans": [],
            "key_algorithm": "RSA",
            "key_size": 2048,
            "hash_algorithm": "SHA256",
            "validity_days": 365,
            "usage_preset": "server_tls",
            "environment_tags": ["api"],
            "owner": "api-tests",
            "return_private_key": True,
        },
    )
    assert response.status_code == 201
    payload = response.json()
    assert "BEGIN CERTIFICATE" in payload["certificate_pem"]
    assert "BEGIN RSA PRIVATE KEY" in payload["private_key_pem"]
    assert payload["metadata"]["issuer_ca_id"] == ca_id
    cert_id = payload["certificate_id"]

    record = db_session.get(Certificate, cert_id)
    assert record is not None
    assert record.common_name == "issued.api.lab"
    assert record.environment_tags == ["api"]


def test_self_signed_certificate_via_api(client, db_session):
    token_value = _create_api_token(client, {"issue": True})
    response = client.post(
        "/api/v1/certificates",
        headers={"Authorization": f"Bearer {token_value}"},
        json={
            "issuer_ca_id": None,
            "common_name": "self.api.lab",
            "dns_sans": ["self.api.lab"],
            "key_algorithm": "ECDSA",
            "curve": "P-256",
            "hash_algorithm": "SHA256",
            "validity_days": 30,
            "return_private_key": True,
        },
    )
    assert response.status_code == 201
    payload = response.json()
    assert payload["metadata"]["issuer_ca_id"] is None
    assert "BEGIN CERTIFICATE" in payload["certificate_pem"]
    assert "PRIVATE KEY" in payload["private_key_pem"]


def test_get_certificate_with_read_token(client, db_session):
    ca_id = _create_ca(db_session)
    issue_token = _create_api_token(client, {"issue": True, "read": True})
    issue_response = client.post(
        "/api/v1/certificates",
        headers={"Authorization": f"Bearer {issue_token}"},
        json={
            "issuer_ca_id": ca_id,
            "common_name": "readable.lab",
            "dns_sans": [],
            "key_algorithm": "RSA",
            "key_size": 2048,
            "hash_algorithm": "SHA256",
            "validity_days": 90,
            "return_private_key": True,
        },
    )
    cert_id = issue_response.json()["certificate_id"]

    read_token = _create_api_token(client, {"read": True})
    response = client.get(
        f"/api/v1/certificates/{cert_id}?include_private_key=true",
        headers={"Authorization": f"Bearer {read_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["certificate_id"] == cert_id
    assert "BEGIN CERTIFICATE" in body["certificate_pem"]
    assert "PRIVATE KEY" in body["private_key_pem"]


def test_expired_token_is_rejected(client, db_session):
    ca_id = _create_ca(db_session)
    token, raw_value = create_token(
        "expired",
        {"issue": True, "read": False},
        datetime.now(timezone.utc) - timedelta(days=1),
        db_session,
    )
    past_token = raw_value

    response = client.post(
        "/api/v1/certificates",
        headers={"Authorization": f"Bearer {past_token}"},
        json={
            "issuer_ca_id": ca_id,
            "common_name": "fail.lab",
            "dns_sans": [],
            "key_algorithm": "RSA",
            "key_size": 2048,
            "hash_algorithm": "SHA256",
            "validity_days": 30,
        },
    )
    assert response.status_code == 401


def test_invalid_token_header_returns_401(client, db_session):
    response = client.get(
        "/api/v1/certificates/unknown",
        headers={"Authorization": "Bearer invalid"},
    )
    assert response.status_code == 401
