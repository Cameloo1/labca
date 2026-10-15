"""Tests for ``python -m app.cli prune`` and ``crl regenerate``."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from sqlalchemy import select

from app import cli
from app.config import get_settings
from app.models import (
    AuditLog,
    CAStatusEnum,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
    CrlRecord,
    NotificationLog,
    NotificationRule,
)
from app.schemas import RootCAConfig
from app.services import keystore
from app.services.ca_service import create_root_ca
from tests.cli_support import run, run_json

NOW = datetime.now(timezone.utc)


def _cert(db, serial: str, *, expired_days_ago: float, spiffe: bool) -> Certificate:
    cert = Certificate(
        id=str(uuid.uuid4()),
        type=CertificateTypeEnum.LEAF,
        common_name=serial,
        san_dns=[],
        san_ips=[],
        serial_number=serial,
        not_before=NOW - timedelta(days=expired_days_ago + 1),
        not_after=NOW - timedelta(days=expired_days_ago),
        key_algorithm="ECDSA",
        key_size=256,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        cert_pem="PEM",
        is_ephemeral=False,
        issued_to_spiffe_id="spiffe://labca.example.test/ns/a/sa/b" if spiffe else None,
    )
    db.add(cert)
    db.commit()
    return cert


def _serials(db) -> set[str]:
    db.expire_all()
    return {c.serial_number for c in db.scalars(select(Certificate)).all()}


def _seed(db) -> None:
    _cert(db, "old-workload", expired_days_ago=10, spiffe=True)
    _cert(db, "older-workload", expired_days_ago=40, spiffe=True)
    _cert(db, "recent-workload", expired_days_ago=2, spiffe=True)
    _cert(db, "old-admin", expired_days_ago=100, spiffe=False)
    db.add(Certificate(**_live_fields("live-workload")))
    db.commit()


def _live_fields(serial: str) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "type": CertificateTypeEnum.LEAF,
        "common_name": serial,
        "san_dns": [],
        "san_ips": [],
        "serial_number": serial,
        "not_before": NOW - timedelta(days=1),
        "not_after": NOW + timedelta(days=1),
        "key_algorithm": "ECDSA",
        "key_size": 256,
        "status": CertificateStatusEnum.ACTIVE,
        "environment_tags": [],
        "cert_pem": "PEM",
        "is_ephemeral": False,
        "issued_to_spiffe_id": "spiffe://labca.example.test/ns/a/sa/c",
    }


# --- prune ------------------------------------------------------------------------------


def test_prune_deletes_only_old_expired_workload_certs(capsys, db_session, SessionLocal):
    _seed(db_session)
    code, result = run_json(capsys, ["prune", "--expired-workload-older-than-days", "7"], session_factory=SessionLocal)
    assert code == 0
    assert result["deleted"] == 2
    assert result["dry_run"] is False
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", result["cutoff"])
    assert _serials(db_session) == {"recent-workload", "old-admin", "live-workload"}

    audit = db_session.scalars(select(AuditLog).where(AuditLog.action == "PRUNE_WORKLOAD_CERTS")).one()
    assert audit.actor_id == "cli"
    assert audit.details_json["deleted"] == 2


def test_prune_dry_run_deletes_nothing_and_writes_no_audit(capsys, db_session, SessionLocal):
    _seed(db_session)
    code, result = run_json(
        capsys, ["prune", "--expired-workload-older-than-days", "7", "--dry-run"], session_factory=SessionLocal
    )
    assert code == 0
    assert result["deleted"] == 2
    assert result["dry_run"] is True
    assert len(_serials(db_session)) == 5
    assert db_session.scalars(select(AuditLog).where(AuditLog.action == "PRUNE_WORKLOAD_CERTS")).all() == []


def test_prune_respects_larger_crl_retention(capsys, monkeypatch, db_session, SessionLocal):
    _seed(db_session)
    monkeypatch.setenv("CRL_RETENTION_AFTER_EXPIRY_HOURS", str(24 * 30))  # 30 days beats the 7 day request
    get_settings.cache_clear()
    code, result = run_json(capsys, ["prune", "--expired-workload-older-than-days", "7"], session_factory=SessionLocal)
    assert code == 0
    assert result["deleted"] == 1  # only the 40 day old one is past the 30 day floor
    assert "older-workload" not in _serials(db_session)
    assert "old-workload" in _serials(db_session)
    cutoff = datetime.fromisoformat(result["cutoff"].replace("Z", "+00:00"))
    assert abs((datetime.now(timezone.utc) - cutoff) - timedelta(days=30)) < timedelta(minutes=5)


def test_prune_removes_notification_logs_of_deleted_certs(capsys, db_session, SessionLocal):
    victim = _cert(db_session, "old-workload", expired_days_ago=10, spiffe=True)
    rule = NotificationRule(days_before_expiry=7, delivery_methods_json={})
    db_session.add(rule)
    db_session.commit()
    db_session.add(NotificationLog(certificate_id=victim.id, rule_id=rule.id, delivery_method="email"))
    db_session.commit()
    code, _result = run_json(capsys, ["prune", "--expired-workload-older-than-days", "1"], session_factory=SessionLocal)
    assert code == 0
    assert db_session.scalars(select(NotificationLog)).all() == []


def test_prune_rejects_days_below_one(capsys, db_session, SessionLocal):
    _seed(db_session)
    code, out, err = run(capsys, ["prune", "--expired-workload-older-than-days", "0"], session_factory=SessionLocal)
    assert code == 2
    assert out == ""
    assert "at least 1" in err
    assert len(_serials(db_session)) == 5


def test_prune_with_nothing_to_delete(capsys, db_session, SessionLocal):
    code, result = run_json(capsys, ["prune", "--expired-workload-older-than-days", "3"], session_factory=SessionLocal)
    assert code == 0
    assert result["deleted"] == 0


# --- crl regenerate ---------------------------------------------------------------------


def _root(db, name="CRL CA") -> CertificateAuthority:
    return create_root_ca(
        RootCAConfig(
            name=name,
            subject_cn=name,
            key_algorithm="ECDSA",
            curve="P-256",
            hash_algorithm="SHA256",
            validity_years=1,
            path_length=1,
        ),
        db,
    )


def test_crl_regenerate_bumps_number(capsys, db_session, SessionLocal):
    ca = _root(db_session)
    code, first = run_json(capsys, ["crl", "regenerate", "--ca-name", "CRL CA"], session_factory=SessionLocal)
    assert code == 0
    assert set(first) == {"ca_id", "crl_number", "this_update", "next_update", "revoked_count"}
    assert first["ca_id"] == ca.id
    assert first["crl_number"] == 1
    assert first["revoked_count"] == 0
    assert first["this_update"] < first["next_update"]
    code, second = run_json(capsys, ["crl", "regenerate", "--ca-name", "CRL CA"], session_factory=SessionLocal)
    assert code == 0
    assert second["crl_number"] == 2
    db_session.expire_all()
    record = db_session.scalars(select(CrlRecord).where(CrlRecord.ca_id == ca.id)).one()
    assert record.crl_number == 2
    assert x509.load_der_x509_crl(record.der).issuer == x509.load_pem_x509_certificate(ca.cert_pem.encode()).subject


def test_crl_regenerate_unknown_name(capsys, db_session, SessionLocal):
    _root(db_session)
    code, out, err = run(capsys, ["crl", "regenerate", "--ca-name", "Nope"], session_factory=SessionLocal)
    assert code == 1
    assert out == ""
    assert err.strip() == "error: no active CA named 'Nope' with a key"


def test_crl_regenerate_ambiguous_name(capsys, db_session, SessionLocal):
    _root(db_session, "Twin")
    _root(db_session, "Twin")
    code, _out, err = run(capsys, ["crl", "regenerate", "--ca-name", "Twin"], session_factory=SessionLocal)
    assert code == 1
    assert err.strip() == "error: CA name 'Twin' is ambiguous"


def test_crl_regenerate_keyless_ca(capsys, db_session, SessionLocal):
    ca = _root(db_session, "Keyless")
    ca.key_encrypted_pem = None
    db_session.commit()
    code, _out, err = run(capsys, ["crl", "regenerate", "--ca-name", "Keyless"], session_factory=SessionLocal)
    assert code == 1
    assert err.strip() == "error: no active CA named 'Keyless' with a key"


def test_crl_regenerate_ignores_disabled_ca(capsys, db_session, SessionLocal):
    ca = _root(db_session, "Disabled")
    ca.status = CAStatusEnum.DISABLED
    db_session.commit()
    code, _out, err = run(capsys, ["crl", "regenerate", "--ca-name", "Disabled"], session_factory=SessionLocal)
    assert code == 1
    assert "no active CA" in err


def test_crl_regenerate_unavailable_key(capsys, monkeypatch, db_session, SessionLocal):
    _root(db_session, "Sealed")
    monkeypatch.delenv("LABCA_KEK_TEST_1")
    monkeypatch.setenv("LABCA_KEK_OTHER", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
    monkeypatch.setenv("LABCA_ACTIVE_KEK_ID", "other")
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()
    code, out, err = run(capsys, ["crl", "regenerate", "--ca-name", "Sealed"], session_factory=SessionLocal)
    assert code == 1
    assert out == ""
    assert "key is unavailable" in err
    assert "labca:v1:" not in err


@pytest.mark.parametrize("args", [["prune"], ["crl"], ["crl", "regenerate"]])
def test_usage_errors_exit_2(args):
    with pytest.raises(SystemExit) as info:
        cli.main(args)
    assert info.value.code == 2
