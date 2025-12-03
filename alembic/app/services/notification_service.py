from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Tuple

from sqlalchemy.orm import Session

from app.models import Certificate, NotificationLog, NotificationRule

DEFAULT_RULE_OFFSETS = [30, 7, 1]
DEFAULT_DELIVERY_METHODS = {"email": True, "webhook": False}


def ensure_default_rules(db: Session) -> list[NotificationRule]:
    existing = {
        rule.days_before_expiry: rule
        for rule in db.query(NotificationRule).all()
    }
    created = False
    for offset in DEFAULT_RULE_OFFSETS:
        if offset not in existing:
            rule = NotificationRule(
                days_before_expiry=offset,
                enabled=True,
                delivery_methods_json=DEFAULT_DELIVERY_METHODS.copy(),
            )
            db.add(rule)
            created = True
    if created:
        db.commit()
    return (
        db.query(NotificationRule)
        .order_by(NotificationRule.days_before_expiry.desc())
        .all()
    )


def update_rules(
    db: Session,
    updates: Iterable[Tuple[int, bool, dict]],
) -> list[NotificationRule]:
    updated_rules: list[NotificationRule] = []
    for rule_id, enabled, delivery_methods in updates:
        rule = db.get(NotificationRule, rule_id)
        if not rule:
            continue
        rule.enabled = enabled
        rule.delivery_methods_json = delivery_methods
        db.add(rule)
        updated_rules.append(rule)
    if updated_rules:
        db.commit()
        for rule in updated_rules:
            db.refresh(rule)
    return updated_rules


def evaluate_rules_for_date(
    db: Session,
    reference_date: datetime | None = None,
) -> list[NotificationLog]:
    """Placeholder scheduler logic. Returns logs for certificates matching active rules."""
    reference = reference_date or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    rules = (
        db.query(NotificationRule)
        .filter(NotificationRule.enabled.is_(True))
        .order_by(NotificationRule.days_before_expiry.desc())
        .all()
    )
    generated_logs: list[NotificationLog] = []

    for rule in rules:
        window_start = _start_of_day(reference + timedelta(days=rule.days_before_expiry))
        window_end = window_start + timedelta(days=1)
        certificates = (
            db.query(Certificate)
            .filter(Certificate.not_after >= window_start)
            .filter(Certificate.not_after < window_end)
            .all()
        )
        for certificate in certificates:
            for method, enabled in (rule.delivery_methods_json or {}).items():
                if not enabled:
                    continue
                log = NotificationLog(
                    certificate_id=certificate.id,
                    rule_id=rule.id,
                    delivery_method=method,
                    status="pending",
                    message=f"Notify via {method} for certificate {certificate.common_name} expiring in {rule.days_before_expiry} days.",
                )
                db.add(log)
                generated_logs.append(log)

    if generated_logs:
        db.commit()
        for log in generated_logs:
            db.refresh(log)
    return generated_logs


def _start_of_day(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return datetime(moment.year, moment.month, moment.day, tzinfo=timezone.utc)
