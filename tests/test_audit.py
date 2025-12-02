from __future__ import annotations

import pytest

from app.models import AuditLog, ActorType
from app.schemas import RootCAConfig
from app.services.audit_service import log_action
from app.services.ca_service import create_root_ca


# The API_TOKEN_CREATION_SECRET is already set by conftest.py settings_override fixture
# No additional fixture needed


def _create_ca(db_session):
    config = RootCAConfig(
        name="Audit Root",
        subject_cn="Audit Root",
        validity_years=5,
        key_algorithm="RSA",
        key_size=2048,
    )
    ca = create_root_ca(config, db_session)
    db_session.commit()
    db_session.refresh(ca)
    return ca.id


def test_api_issue_creates_audit_logs(client, db_session):
    ca_id = _create_ca(db_session)
    token_response = client.post(
        "/api/v1/tokens",
        headers={"X-LabCA-Admin-Secret": "unit-secret"},
        json={"name": "audit-test", "permissions": {"issue": True, "read": True}},
    )
    assert token_response.status_code == 201
    token_data = token_response.json()
    raw_token = token_data["token"]

    issue_response = client.post(
        "/api/v1/certificates",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={
            "issuer_ca_id": ca_id,
            "common_name": "audit.lab",
            "dns_sans": ["audit.lab"],
            "key_algorithm": "RSA",
            "key_size": 2048,
            "hash_algorithm": "SHA256",
            "validity_days": 365,
            "usage_preset": "server_tls",
            "return_private_key": True,
        },
    )
    assert issue_response.status_code == 201

    token_logs = db_session.query(AuditLog).filter(AuditLog.action == "CREATE_TOKEN").all()
    assert token_logs
    assert token_logs[0].actor_id == "api-admin"

    cert_logs = db_session.query(AuditLog).filter(AuditLog.action == "ISSUE_CERT").all()
    assert cert_logs
    assert cert_logs[0].actor_type == ActorType.API_TOKEN
    assert cert_logs[0].actor_id == token_data["token_prefix"]


def test_audit_page_lists_entries(client, db_session):
    log_action(
        db_session,
        actor_type=ActorType.SYSTEM,
        actor_id="scheduler",
        action="TEST_EVENT",
        target_type="SYSTEM",
        target_id=None,
        details={"note": "example"},
        ip_address="127.0.0.1",
    )
    db_session.commit()

    response = client.get("/audit")
    assert response.status_code == 200
    assert "TEST_EVENT" in response.text
    assert "scheduler" in response.text
