"""Tests for per-token policy checks, token creation with policy, and token validation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models import ApiToken, AuditLog, AuditStatus, Certificate
from app.schemas import RootCAConfig, TokenPolicy
from app.services.api_token_service import create_token, validate_token
from app.services.ca_service import create_root_ca
from app.services.token_policy import PolicyViolation, can_revoke, check_issuance, policy_for

ADMIN = {"X-LabCA-Admin-Secret": "unit-secret"}


def _check(policy, *, dns=(), ips=(), uris=(), hours=1):
    check_issuance(policy, dns_sans=list(dns), ip_sans=list(ips), uri_sans=list(uris), validity_hours=hours)


def _policy(**kwargs):
    return TokenPolicy(**kwargs)


def test_none_policy_allows_anything():
    _check(None, dns=["x.evil"], ips=["10.0.0.1"], uris=["https://a/"], hours=87600)


def test_dns_exact_and_subdomain_match():
    policy = _policy(allowed_dns_suffixes=["lab.example"])
    _check(policy, dns=["lab.example", "a.b.lab.example"])


def test_dns_wildcard_san_under_suffix():
    policy = _policy(allowed_dns_suffixes=["lab.example"])
    _check(policy, dns=["*.lab.example"])


def test_dns_wildcard_in_policy_suffix():
    policy = _policy(allowed_dns_suffixes=["*.lab.example"])
    _check(policy, dns=["*.lab.example", "x.*.lab.example"])
    with pytest.raises(PolicyViolation):
        _check(policy, dns=["lab.example"])


def test_dns_suffix_must_match_on_label_boundary():
    policy = _policy(allowed_dns_suffixes=["lab.example"])
    with pytest.raises(PolicyViolation, match="DNS SAN 'evil-lab.example' is not allowed by the token policy."):
        _check(policy, dns=["evil-lab.example"])


def test_dns_trailing_dot_and_case_are_normalized():
    policy = _policy(allowed_dns_suffixes=["lab.example"])
    _check(policy, dns=["API.Lab.Example."])


def test_empty_suffix_list_denies_dns():
    with pytest.raises(PolicyViolation):
        _check(_policy(), dns=["a.lab.example"])


def test_ip_sans_denied():
    with pytest.raises(PolicyViolation, match="IP SANs are not allowed by the token policy."):
        _check(_policy(allowed_dns_suffixes=["lab.example"]), ips=["10.0.0.1"])


def test_uri_prefix_match_and_mismatch():
    policy = _policy(allowed_uri_prefixes=["spiffe://lab.example/ns/app/"])
    _check(policy, uris=["spiffe://lab.example/ns/app/sa/web"])
    with pytest.raises(PolicyViolation, match="URI SAN 'spiffe://lab.example/ns/other/x' is not allowed"):
        _check(policy, uris=["spiffe://lab.example/ns/other/x"])


def test_empty_prefix_list_denies_uri():
    with pytest.raises(PolicyViolation):
        _check(_policy(), uris=["spiffe://lab.example/a"])


def test_validity_limit():
    policy = _policy(max_validity_hours=24)
    _check(policy, hours=24)
    with pytest.raises(PolicyViolation, match="Requested validity of 25 hours exceeds the token policy maximum of 24"):
        _check(policy, hours=25)


def _token(db, name="t", policy=None):
    return create_token(name, {"issue": True, "read": True, "revoke": True}, None, db, policy=policy)


def test_can_revoke_matrix(db_session):
    own, _ = _token(db_session, "own")
    other, _ = _token(db_session, "other")
    any_token, _ = _token(db_session, "any", policy=_policy(revoke_any=True).model_dump())
    cert = Certificate(issued_by_token_id=own.id)
    assert can_revoke(own, cert)
    assert not can_revoke(other, cert)
    assert can_revoke(any_token, cert)
    assert policy_for(other) is None
    assert policy_for(any_token).revoke_any is True


@pytest.mark.parametrize(
    "policy",
    [
        {"allowed_dns_suffixes": ["bad suffix!"]},
        {"allowed_dns_suffixes": [""]},
        {"allowed_uri_prefixes": ["http://example.com/"]},
        {"allowed_uri_prefixes": ["https://" + "a" * 2050]},
        {"allowed_uri_prefixes": ["spiffe://lab.example"]},
        {"allowed_uri_prefixes": ["https://example.com"]},
        {"max_validity_hours": 0},
        {"max_validity_hours": 87601},
    ],
)
def test_invalid_policy_gives_422(client, policy):
    response = client.post(
        "/api/v1/tokens", headers=ADMIN, json={"name": "p", "permissions": {"issue": True}, "policy": policy}
    )
    assert response.status_code == 422


def test_suffix_normalization_in_model():
    policy = _policy(allowed_dns_suffixes=["  .Lab.Example "])
    assert policy.allowed_dns_suffixes == ["lab.example"]


def test_create_token_with_policy_stores_and_returns_it(client, db_session):
    policy = {
        "allowed_dns_suffixes": ["lab.example"],
        "allowed_uri_prefixes": ["spiffe://lab.example/"],
        "max_validity_hours": 48,
        "revoke_any": True,
    }
    response = client.post(
        "/api/v1/tokens",
        headers=ADMIN,
        json={"name": "p", "permissions": {"issue": True}, "policy": policy},
    )
    assert response.status_code == 201
    assert response.json()["policy"] == policy
    stored = db_session.get(ApiToken, response.json()["id"])
    assert stored.policy_json == policy


def test_create_token_without_policy_returns_null(client, db_session):
    response = client.post("/api/v1/tokens", headers=ADMIN, json={"name": "p", "permissions": {"issue": True}})
    assert response.status_code == 201
    assert response.json()["policy"] is None
    assert db_session.get(ApiToken, response.json()["id"]).policy_json is None


def test_token_creation_rejects_wrong_secret_of_same_length(client):
    response = client.post(
        "/api/v1/tokens",
        headers={"X-LabCA-Admin-Secret": "unit-secreT"},
        json={"name": "p", "permissions": {"issue": True}},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid admin secret for token creation."


def test_token_creation_rejects_missing_secret(client):
    response = client.post("/api/v1/tokens", json={"name": "p", "permissions": {"issue": True}})
    assert response.status_code == 403


def _ca(db_session):
    config = RootCAConfig(
        name="Policy Root", subject_cn="Policy Root", validity_years=3, key_algorithm="RSA", key_size=2048
    )
    ca = create_root_ca(config, db_session)
    db_session.commit()
    return ca.id


def _issue(client, raw, ca_id, **overrides):
    body = {
        "issuer_ca_id": ca_id,
        "common_name": "svc.lab.example",
        "dns_sans": ["svc.lab.example"],
        "key_algorithm": "ECDSA",
        "curve": "P-256",
        "validity_days": 1,
    }
    body.update(overrides)
    return client.post("/api/v1/certificates", headers={"Authorization": f"Bearer {raw}"}, json=body)


def test_issue_policy_violation_is_403_and_audited(client, db_session):
    ca_id = _ca(db_session)
    _, raw = _token(db_session, policy=_policy(allowed_dns_suffixes=["lab.example"]).model_dump())
    response = _issue(client, raw, ca_id, dns_sans=["evil.example"])
    message = "DNS SAN 'evil.example' is not allowed by the token policy."
    assert response.status_code == 403
    assert response.json()["detail"] == message
    rows = db_session.query(AuditLog).filter(AuditLog.action == "ISSUE_CERT").all()
    assert len(rows) == 1
    assert rows[0].status == AuditStatus.FAILURE
    assert rows[0].details_json == {"reason": message}
    assert db_session.query(Certificate).count() == 0


def test_issue_validity_policy_violation(client, db_session):
    ca_id = _ca(db_session)
    policy = _policy(allowed_dns_suffixes=["lab.example"], max_validity_hours=24).model_dump()
    _, raw = _token(db_session, policy=policy)
    response = _issue(client, raw, ca_id, validity_days=2)
    assert response.status_code == 403
    assert "exceeds the token policy maximum of 24 hours" in response.json()["detail"]


def test_issue_allowed_by_policy_sets_issuer_token(client, db_session):
    ca_id = _ca(db_session)
    policy = _policy(allowed_dns_suffixes=["lab.example"], allowed_uri_prefixes=["spiffe://lab.example/"]).model_dump()
    token, raw = _token(db_session, policy=policy)
    response = _issue(client, raw, ca_id, uri_sans=["spiffe://lab.example/ns/a/sa/b"])
    assert response.status_code == 201
    row = db_session.get(Certificate, response.json()["certificate_id"])
    assert row.issued_by_token_id == token.id
    assert row.san_uris == ["spiffe://lab.example/ns/a/sa/b"]


def test_legacy_token_without_policy_is_unrestricted(client, db_session):
    ca_id = _ca(db_session)
    token, raw = _token(db_session)
    response = _issue(client, raw, ca_id, dns_sans=["anything.example"], ip_sans=["10.1.2.3"])
    assert response.status_code == 201
    assert db_session.get(Certificate, response.json()["certificate_id"]).issued_by_token_id == token.id


def test_self_signed_issuance_records_token_and_rejects_uri_sans(client, db_session):
    token, raw = _token(db_session)
    headers = {"Authorization": f"Bearer {raw}"}
    base = {"common_name": "dev.lab", "key_algorithm": "ECDSA", "curve": "P-256", "validity_days": 1}
    ok = client.post("/api/v1/certificates", headers=headers, json=base)
    assert ok.status_code == 201
    assert db_session.get(Certificate, ok.json()["certificate_id"]).issued_by_token_id == token.id
    bad = client.post("/api/v1/certificates", headers=headers, json={**base, "uri_sans": ["spiffe://lab.example/a"]})
    assert bad.status_code == 422


def test_invalid_uri_san_in_issue_request_is_422(client, db_session):
    ca_id = _ca(db_session)
    _, raw = _token(db_session)
    response = _issue(client, raw, ca_id, uri_sans=["http://insecure.example/"])
    assert response.status_code == 422


def test_validate_token_accepts_correct_token(db_session):
    token, raw = _token(db_session)
    assert validate_token(raw, db_session).id == token.id
    assert token.last_used_at is not None


def test_validate_token_rejects_wrong_token_with_same_prefix(db_session):
    _, raw = _token(db_session)
    assert validate_token(raw[:8] + "x" * 20, db_session) is None
    assert validate_token("", db_session) is None
    assert validate_token("unknown-token-value", db_session) is None


def test_validate_token_rejects_expired_token(db_session):
    _, raw = create_token("old", {"issue": True}, datetime.now(timezone.utc) - timedelta(hours=1), db_session)
    assert validate_token(raw, db_session) is None
