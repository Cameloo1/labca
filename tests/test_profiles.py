from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models import CASourceTypeEnum, CAStatusEnum, CertificateAuthority, Profile


def _seed_ca(db_session) -> str:
    now = datetime.now(timezone.utc)
    ca = CertificateAuthority(
        name="Profile Root",
        source_type=CASourceTypeEnum.ROOT,
        subject_cn="Profile Root",
        subject_json={"CN": "Profile Root"},
        serial_number="PROF-CA",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365),
        key_algorithm="RSA",
        key_size=4096,
        status=CAStatusEnum.ACTIVE,
        cert_pem="-----BEGIN CERTIFICATE-----root-----END CERTIFICATE-----",
    )
    db_session.add(ca)
    db_session.commit()
    db_session.refresh(ca)
    return ca.id


def test_profile_crud_and_issue_prefill(client, db_session):
    ca_id = _seed_ca(db_session)

    payload = {
        "name": "Server Profile",
        "description": "Default server profile",
        "profile_type": "SERVER_TLS",
        "default_issuer_ca_id": ca_id,
        "subject_cn": "web.lab",
        "subject_o": "Lab Org",
        "subject_ou": "",
        "subject_c": "US",
        "subject_st": "",
        "subject_l": "",
        "key_algorithm": "RSA",
        "key_size": "3072",
        "validity_days_default": "400",
        "validity_days_min": "",
        "validity_days_max": "",
        "usage_config_json": '{"is_ca": false, "extended_key_usage": ["serverAuth"]}',
        "output_config_json": '{"output_pem_cert": true}',
        "store_in_db_default": "on",
        "environment_tags_default": "prod,blue",
        "owner_default": "svc-team",
        "available_in_simple_mode": "",
        "active": "on",
    }

    response = client.post("/profiles/new", data=payload, follow_redirects=False)
    assert response.status_code == 303

    listing = client.get("/profiles")
    assert listing.status_code == 200
    assert "Server Profile" in listing.text

    # Get profile id by querying API listing (hack: parse hidden link)
    profile = db_session.query(Profile).first()
    profile_id = profile.id

    issue_form = client.get(f"/cas/{ca_id}/issue", params={"profile_id": profile_id})
    assert issue_form.status_code == 200
    assert 'value="web.lab"' in issue_form.text
    assert 'value="prod,blue"' in issue_form.text
    assert 'value="svc-team"' in issue_form.text
    assert "selected>3072<" in issue_form.text or 'value="3072" selected' in issue_form.text
