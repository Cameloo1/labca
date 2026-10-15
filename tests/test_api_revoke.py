"""Tests for POST /api/v1/certificates/{id}/revoke and the post-revocation hook registry."""

from __future__ import annotations

import pytest

from app.models import AuditLog, AuditStatus, Certificate
from app.schemas import RootCAConfig, TokenPolicy
from app.services import revocation_service
from app.services.api_token_service import create_token
from app.services.ca_service import create_root_ca
from app.services.revocation_service import (
    RFC5280_REASONS,
    clear_post_revoke_hooks,
    register_post_revoke_hook,
    revoke_certificate,
)


@pytest.fixture(autouse=True)
def _clean_hooks():
    clear_post_revoke_hooks()
    yield
    clear_post_revoke_hooks()


def _ca(db_session):
    config = RootCAConfig(
        name="Revoke Root", subject_cn="Revoke Root", validity_years=3, key_algorithm="ECDSA", curve="P-256"
    )
    ca = create_root_ca(config, db_session)
    db_session.commit()
    return ca.id


def _token(db_session, *, revoke: bool = True, policy: dict | None = None, name: str = "tok"):
    token, raw = create_token(name, {"issue": True, "read": True, "revoke": revoke}, None, db_session, policy=policy)
    return token, {"Authorization": f"Bearer {raw}"}


def _issue(client, headers, ca_id) -> str:
    response = client.post(
        "/api/v1/certificates",
        headers=headers,
        json={
            "issuer_ca_id": ca_id,
            "common_name": "rev.lab.example",
            "key_algorithm": "ECDSA",
            "curve": "P-256",
            "validity_days": 1,
        },
    )
    assert response.status_code == 201
    return response.json()["certificate_id"]


def _revoke(client, headers, cert_id, **body):
    return client.post(f"/api/v1/certificates/{cert_id}/revoke", headers=headers, json=body)


def _audit(db_session, action):
    return db_session.query(AuditLog).filter(AuditLog.action == action).all()


def test_revoke_own_certificate(client, db_session):
    ca_id = _ca(db_session)
    token, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)

    response = _revoke(client, headers, cert_id, reason="keyCompromise")

    assert response.status_code == 200
    body = response.json()
    row = db_session.get(Certificate, cert_id)
    db_session.refresh(row)
    assert body["revoked"] is True
    assert body["certificate_id"] == cert_id
    assert body["serial_hex"] == row.serial_number
    assert body["reason"] == "keyCompromise"
    assert body["revoked_at"]
    assert row.revoked_at is not None
    assert row.revocation_reason_code == "keyCompromise"
    assert row.revocation_reason == "keyCompromise"
    rows = _audit(db_session, "REVOKE_CERT")
    assert len(rows) == 1
    assert rows[0].status == AuditStatus.SUCCESS
    assert rows[0].actor_id == token.token_prefix
    assert rows[0].details_json == {"reason": "keyCompromise", "via": "api"}


def test_revoke_defaults_to_unspecified(client, db_session):
    ca_id = _ca(db_session)
    _, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)
    response = _revoke(client, headers, cert_id)
    assert response.status_code == 200
    assert response.json()["reason"] == "unspecified"


def test_revoke_other_tokens_certificate_forbidden(client, db_session):
    ca_id = _ca(db_session)
    _, headers_a = _token(db_session, name="a")
    token_b, headers_b = _token(db_session, name="b")
    cert_id = _issue(client, headers_a, ca_id)

    response = _revoke(client, headers_b, cert_id)

    assert response.status_code == 403
    assert response.json()["detail"] == "API token may only revoke certificates it issued."
    row = db_session.get(Certificate, cert_id)
    db_session.refresh(row)
    assert row.revoked_at is None
    rows = _audit(db_session, "REVOKE_CERT")
    assert len(rows) == 1
    assert rows[0].status == AuditStatus.FAILURE
    assert rows[0].actor_id == token_b.token_prefix
    assert rows[0].details_json == {"reason": "not_owner"}


def test_revoke_any_policy_allows_other(client, db_session):
    ca_id = _ca(db_session)
    _, headers_a = _token(db_session, name="a")
    _, headers_b = _token(db_session, name="b", policy=TokenPolicy(revoke_any=True).model_dump())
    cert_id = _issue(client, headers_a, ca_id)

    response = _revoke(client, headers_b, cert_id, reason="superseded")

    assert response.status_code == 200
    row = db_session.get(Certificate, cert_id)
    db_session.refresh(row)
    assert row.revocation_reason_code == "superseded"


def test_revoke_requires_permission(client, db_session):
    ca_id = _ca(db_session)
    _, issuer = _token(db_session, name="issuer")
    _, no_revoke = _token(db_session, revoke=False, name="norevoke")
    cert_id = _issue(client, issuer, ca_id)
    response = _revoke(client, no_revoke, cert_id)
    assert response.status_code == 403
    assert response.json()["detail"] == "API token is not permitted to revoke certificates."


def test_revoke_without_auth(client, db_session):
    response = client.post("/api/v1/certificates/some-id/revoke", json={})
    assert response.status_code == 401


def test_revoke_unknown(client, db_session):
    _, headers = _token(db_session)
    response = _revoke(client, headers, "does-not-exist")
    assert response.status_code == 404
    assert response.json()["detail"] == "Certificate not found."


def test_revoke_twice(client, db_session):
    ca_id = _ca(db_session)
    _, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)
    assert _revoke(client, headers, cert_id).status_code == 200
    second = _revoke(client, headers, cert_id)
    assert second.status_code == 409
    assert second.json()["detail"] == "Certificate is already revoked."


def test_revoke_bad_reason(client, db_session):
    ca_id = _ca(db_session)
    _, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)
    response = _revoke(client, headers, cert_id, reason="because")
    assert response.status_code == 422
    row = db_session.get(Certificate, cert_id)
    assert row.revoked_at is None


@pytest.mark.parametrize("reason", RFC5280_REASONS)
def test_every_rfc5280_reason_is_accepted(client, db_session, reason):
    ca_id = _ca(db_session)
    _, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)
    assert _revoke(client, headers, cert_id, reason=reason).status_code == 200
    row = db_session.get(Certificate, cert_id)
    db_session.refresh(row)
    assert row.revocation_reason_code == reason


def test_post_revoke_hooks_called_and_errors_contained(client, db_session, monkeypatch):
    ca_id = _ca(db_session)
    _, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)
    seen: list[str] = []
    logged: list[tuple[str, dict]] = []

    def recorder(certificate, session):
        seen.append(certificate.id)

    def failing(certificate, session):
        raise RuntimeError("hook exploded")

    monkeypatch.setattr(
        revocation_service.logger,
        "exception",
        lambda message, *args, **kwargs: logged.append((message, kwargs.get("extra", {}))),
    )
    register_post_revoke_hook(failing)
    register_post_revoke_hook(recorder)

    response = _revoke(client, headers, cert_id)

    assert response.status_code == 200
    assert seen == [cert_id]
    assert logged == [("Post-revocation hook failed", {"certificate_id": cert_id})]
    row = db_session.get(Certificate, cert_id)
    db_session.refresh(row)
    assert row.revoked_at is not None


def test_clear_post_revoke_hooks_removes_hooks(client, db_session):
    ca_id = _ca(db_session)
    _, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)
    seen: list[str] = []
    register_post_revoke_hook(lambda certificate, session: seen.append(certificate.id))
    clear_post_revoke_hooks()
    assert _revoke(client, headers, cert_id).status_code == 200
    assert seen == []


def test_revoke_certificate_rejects_unknown_reason_code(client, db_session):
    ca_id = _ca(db_session)
    _, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)
    row = db_session.get(Certificate, cert_id)
    with pytest.raises(ValueError):
        revoke_certificate(row, "x", db_session, reason_code="bogus")
    db_session.refresh(row)
    assert row.revoked_at is None


def test_ui_revoke_sets_rfc5280_code(client, db_session, csrf):
    ca_id = _ca(db_session)
    _, headers = _token(db_session)
    cert_id = _issue(client, headers, ca_id)

    response = client.post(
        f"/certificates/{cert_id}/revoke",
        data={"reason_code": "key_compromise", "notes": "lost laptop", **csrf(client)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    row = db_session.get(Certificate, cert_id)
    db_session.refresh(row)
    assert row.revocation_reason_code == "keyCompromise"
    assert row.revocation_reason == "Key compromise - lost laptop"
    assert row.revoked_at is not None
