from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models import Certificate, CertificateStatusEnum, CertificateTypeEnum, NotificationRule
from app.services.notification_service import ensure_default_rules, evaluate_rules_for_date


def test_notifications_page_loads_with_defaults(client, db_session):
    response = client.get("/notifications")
    assert response.status_code == 200
    for window in ["30 day", "7 day", "1 day"]:
        assert window in response.text


def test_notifications_update_rules(client, db_session, csrf):
    response = client.get("/notifications")
    assert response.status_code == 200
    rules = _collect_rules(db_session)
    post_payload = {}
    for rule in rules:
        post_payload[f"rule-{rule.id}-enabled"] = "on"
        post_payload[f"rule-{rule.id}-email"] = "on"
        if rule.days_before_expiry == 7:
            # disable webhook for 7-day rule
            continue
        post_payload[f"rule-{rule.id}-webhook"] = "on"

    update = client.post("/notifications", data={**post_payload, **csrf(client)}, follow_redirects=False)
    assert update.status_code == 303

    refreshed = _collect_rules(db_session)
    seven_rule = next(rule for rule in refreshed if rule.days_before_expiry == 7)
    assert seven_rule.delivery_methods_json.get("webhook") is False
    assert seven_rule.delivery_methods_json.get("email") is True


def test_scheduler_placeholder_creates_logs(db_session):
    reference = datetime(2025, 1, 1, tzinfo=timezone.utc)
    ensure_default_rules(db_session)
    rule_7 = db_session.query(NotificationRule).filter(NotificationRule.days_before_expiry == 7).one()
    rule_7.delivery_methods_json = {"email": True, "webhook": False}
    db_session.add(rule_7)

    certificate = Certificate(
        ca_id=None,
        common_name="expiring.lab",
        san_dns=[],
        san_ips=[],
        serial_number="abc123",
        not_before=reference,
        not_after=reference + timedelta(days=7, hours=1),
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        owner=None,
        cert_pem="-----BEGIN CERTIFICATE-----\nMIABC\n-----END CERTIFICATE-----",
        stored_key_encrypted_pem=None,
        is_ephemeral=False,
        type=CertificateTypeEnum.LEAF,
    )
    db_session.add(certificate)
    db_session.commit()

    logs = evaluate_rules_for_date(db_session, reference_date=reference)
    assert len(logs) == 1
    assert logs[0].certificate_id == certificate.id
    assert logs[0].delivery_method == "email"


def test_compute_expiring_certs_for_rule(db_session):
    """Test compute_expiring_certs_for_rule function returns correct cert IDs."""
    reference = datetime(2025, 1, 1, tzinfo=timezone.utc)
    ensure_default_rules(db_session)

    # Get rule for 30 days before expiry
    rule_30 = db_session.query(NotificationRule).filter(NotificationRule.days_before_expiry == 30).first()
    assert rule_30 is not None

    # Create certificates with various expiry dates
    cert1 = Certificate(
        ca_id=None,
        common_name="expires-in-30.lab",
        san_dns=[],
        san_ips=[],
        serial_number="CERT1",
        not_before=reference - timedelta(days=365),
        not_after=reference + timedelta(days=30),  # Expires in 30 days
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        owner=None,
        cert_pem="-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----",
        stored_key_encrypted_pem=None,
        is_ephemeral=False,
        type=CertificateTypeEnum.LEAF,
    )

    cert2 = Certificate(
        ca_id=None,
        common_name="expires-in-7.lab",
        san_dns=[],
        san_ips=[],
        serial_number="CERT2",
        not_before=reference - timedelta(days=365),
        not_after=reference + timedelta(days=7),  # Expires in 7 days (should not match 30-day rule)
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        owner=None,
        cert_pem="-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----",
        stored_key_encrypted_pem=None,
        is_ephemeral=False,
        type=CertificateTypeEnum.LEAF,
    )

    db_session.add_all([cert1, cert2])
    db_session.commit()

    # Test the function
    logs = evaluate_rules_for_date(db_session, reference_date=reference)

    # Find logs for the 30-day rule
    rule_30_logs = [log for log in logs if log.rule_id == rule_30.id]

    # Should find cert1 (expires in 30 days) but not cert2 (expires in 7 days)
    cert_ids = [log.certificate_id for log in rule_30_logs]
    assert cert1.id in cert_ids
    assert cert2.id not in cert_ids


def _collect_rules(db_session):
    ensure_default_rules(db_session)
    return db_session.query(NotificationRule).order_by(NotificationRule.id.asc()).all()
