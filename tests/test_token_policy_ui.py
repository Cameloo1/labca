"""Tests for the policy fields on the /api token form."""

from __future__ import annotations

from app.models import ApiToken


def _form(**overrides):
    data = {
        "name": "ui-token",
        "perm_issue": "on",
        "perm_read": "on",
        "admin_secret": "unit-secret",
    }
    data.update(overrides)
    return data


def test_form_with_policy_creates_token_and_lists_summary(client, db_session):
    response = client.post(
        "/api",
        data=_form(
            policy_enabled="on",
            policy_dns_suffixes="lab.example, svc.lab.example",
            policy_uri_prefixes="spiffe://lab.example/ns/app/",
            policy_max_validity_hours="24",
            policy_revoke_any="on",
        ),
    )

    assert response.status_code == 200
    token = db_session.query(ApiToken).one()
    assert token.policy_json == {
        "allowed_dns_suffixes": ["lab.example", "svc.lab.example"],
        "allowed_uri_prefixes": ["spiffe://lab.example/ns/app/"],
        "max_validity_hours": 24,
        "revoke_any": True,
    }
    assert "DNS: lab.example, svc.lab.example; URI: spiffe://lab.example/ns/app/; max 24h; revoke any" in response.text
    assert "Policy" in response.text


def test_form_with_minimal_policy_summary(client, db_session):
    response = client.post("/api", data=_form(policy_enabled="on", policy_dns_suffixes="lab.example"))
    assert response.status_code == 200
    assert "DNS: lab.example; max 2160h" in response.text


def test_invalid_suffix_is_rejected_without_creating_token(client, db_session):
    response = client.post("/api", data=_form(policy_enabled="on", policy_dns_suffixes="bad suffix!"))

    assert response.status_code == 400
    assert "Invalid policy" in response.text
    assert "bad suffix!" in response.text
    assert db_session.query(ApiToken).count() == 0


def test_invalid_uri_prefix_and_validity_are_rejected(client, db_session):
    bad_prefix = client.post("/api", data=_form(policy_enabled="on", policy_uri_prefixes="http://x/"))
    assert bad_prefix.status_code == 400
    bad_hours = client.post("/api", data=_form(policy_enabled="on", policy_max_validity_hours="0"))
    assert bad_hours.status_code == 400
    not_a_number = client.post("/api", data=_form(policy_enabled="on", policy_max_validity_hours="abc"))
    assert not_a_number.status_code == 400
    assert "whole number of hours" in not_a_number.text
    assert db_session.query(ApiToken).count() == 0


def test_policy_disabled_creates_token_without_policy(client, db_session):
    response = client.post("/api", data=_form(policy_dns_suffixes="lab.example"))

    assert response.status_code == 200
    token = db_session.query(ApiToken).one()
    assert token.policy_json is None
    assert "None" in response.text


def test_wrong_admin_secret_of_same_length_is_rejected(client, db_session):
    response = client.post("/api", data=_form(admin_secret="unit-secreT"))

    assert response.status_code == 400
    assert "Admin secret is incorrect." in response.text
    assert db_session.query(ApiToken).count() == 0
