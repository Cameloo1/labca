"""Tests for ``python -m app.cli kek status|rewrap``."""

from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app import cli
from app.models import (
    ActorType,
    AuditLog,
    CASourceTypeEnum,
    CAStatusEnum,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
)
from app.services.keystore import CA_KEY_COLUMN, CA_KEY_TABLE, CERT_KEY_COLUMN, CERT_KEY_TABLE, KeyRing, aad_for

KEK1 = bytes(range(32))
KEK2 = bytes(range(32, 64))


def _ring(active: str = "k1") -> KeyRing:
    return KeyRing({"k1": KEK1, "k2": KEK2}, active_kek_id=active)


def _add_ca(db, ring: KeyRing, kek: str | None, serial: str, plaintext: bytes = b"ca-key") -> CertificateAuthority:
    now = datetime.now(timezone.utc)
    ca_id = str(uuid.uuid4())
    if kek is None:
        value = None
    else:
        value = KeyRing({kek: KEK1 if kek == "k1" else KEK2}, active_kek_id=kek).seal(
            plaintext, aad_for(CA_KEY_TABLE, ca_id, CA_KEY_COLUMN)
        )
    ca = CertificateAuthority(
        id=ca_id,
        name=f"CA {serial}",
        source_type=CASourceTypeEnum.ROOT,
        subject_cn=f"CA {serial}",
        subject_json={},
        serial_number=serial,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=100),
        key_algorithm="RSA",
        key_size=2048,
        status=CAStatusEnum.ACTIVE,
        cert_pem="PEM",
        key_encrypted_pem=value,
    )
    db.add(ca)
    db.commit()
    return ca


def _add_cert(db, kek: str | None, serial: str, plaintext: bytes = b"cert-key", raw: str | None = None, aad_id=None):
    now = datetime.now(timezone.utc)
    cert_id = str(uuid.uuid4())
    value = raw
    if raw is None and kek is not None:
        value = KeyRing({kek: KEK1 if kek == "k1" else KEK2}, active_kek_id=kek).seal(
            plaintext, aad_for(CERT_KEY_TABLE, aad_id or cert_id, CERT_KEY_COLUMN)
        )
    cert = Certificate(
        id=cert_id,
        type=CertificateTypeEnum.LEAF,
        common_name=serial,
        san_dns=[],
        san_ips=[],
        serial_number=serial,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=100),
        key_algorithm="RSA",
        key_size=2048,
        status=CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        cert_pem="PEM",
        is_ephemeral=False,
        stored_key_encrypted_pem=value,
    )
    db.add(cert)
    db.commit()
    return cert


def _seed(db) -> None:
    ring = _ring()
    _add_ca(db, ring, "k1", "ca-1")
    _add_ca(db, ring, "k2", "ca-2")
    _add_ca(db, ring, None, "ca-3")
    _add_cert(db, "k1", "cert-1")
    _add_cert(db, "k1", "cert-2")
    _add_cert(db, "k2", "cert-3")
    _add_cert(db, None, "cert-4")


def _values(db) -> dict[str, str | None]:
    db.expire_all()
    result: dict[str, str | None] = {}
    for ca in db.scalars(select(CertificateAuthority)).all():
        result[f"ca:{ca.id}"] = ca.key_encrypted_pem
    for cert in db.scalars(select(Certificate)).all():
        result[f"cert:{cert.id}"] = cert.stored_key_encrypted_pem
    return result


def _rewrap_audits(db) -> list[AuditLog]:
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(AuditLog.action == "KEK_REWRAP")).all())


def test_kek_status_counts(db_session, SessionLocal, capsys):
    _seed(db_session)
    legacy = _add_cert(db_session, None, "cert-legacy", raw="enc::" + base64.b64encode(b"old").decode())
    bad = _add_cert(db_session, None, "cert-bad", raw="not-a-token")
    ring = _ring()
    token_parts = [part for value in _values(db_session).values() if value for part in value.split(":")[3:]]

    code = cli.main(["kek", "status"], session_factory=SessionLocal, keyring=ring)

    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(out) == {
        "active_kek_id": "k1",
        "loaded_kek_ids": ["k1", "k2"],
        "records": {"k1": 3, "k2": 2},
        "by_column": {
            "certificate_authorities.key_encrypted_pem": {"k1": 1, "k2": 1},
            "certificates.stored_key_encrypted_pem": {"k1": 2, "k2": 1},
        },
        "legacy": 1,
        "malformed": 1,
    }
    assert legacy.id and bad.id
    for part in token_parts:
        assert part not in out
    assert base64.b64encode(KEK1).decode() not in out
    assert base64.b64encode(KEK2).decode() not in out


def test_kek_status_includes_unloaded_kek_ids(db_session, SessionLocal, capsys):
    _seed(db_session)
    code = cli.main(["kek", "status"], session_factory=SessionLocal, keyring=KeyRing({"k2": KEK2}, "k2"))
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["records"] == {"k1": 3, "k2": 2}
    assert report["loaded_kek_ids"] == ["k2"]


def test_kek_rewrap_dry_run_changes_nothing(db_session, SessionLocal, capsys):
    _seed(db_session)
    before = _values(db_session)

    code = cli.main(["kek", "rewrap", "--to", "k2", "--dry-run"], session_factory=SessionLocal, keyring=_ring())

    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report == {
        "to_kek_id": "k2",
        "dry_run": True,
        "rewrapped": 3,
        "already_current": 2,
        "by_source_kek": {"k1": 3},
    }
    assert _values(db_session) == before
    assert _rewrap_audits(db_session) == []


def test_kek_rewrap_moves_all_records_and_audits(db_session, SessionLocal, capsys):
    _seed(db_session)
    ring = _ring()

    code = cli.main(["kek", "rewrap", "--to", "k2"], session_factory=SessionLocal, keyring=ring)

    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["dry_run"] is False
    assert (report["rewrapped"], report["already_current"], report["by_source_kek"]) == (3, 2, {"k1": 3})

    assert cli.main(["kek", "status"], session_factory=SessionLocal, keyring=ring) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["records"] == {"k2": 5}

    audits = _rewrap_audits(db_session)
    assert len(audits) == 1
    assert audits[0].actor_type == ActorType.SYSTEM
    assert audits[0].actor_id == "cli"
    assert audits[0].target_type == "KEK"
    assert audits[0].target_id == "k2"
    assert audits[0].details_json == {
        "to_kek_id": "k2",
        "rewrapped": 3,
        "already_current": 2,
        "by_source_kek": {"k1": 3},
    }

    only_k2 = KeyRing({"k2": KEK2})
    db_session.expire_all()
    for ca in db_session.scalars(select(CertificateAuthority)).all():
        if ca.key_encrypted_pem:
            assert only_k2.unseal(ca.key_encrypted_pem, aad_for(CA_KEY_TABLE, ca.id, CA_KEY_COLUMN)) == b"ca-key"
    for cert in db_session.scalars(select(Certificate)).all():
        if cert.stored_key_encrypted_pem:
            assert (
                only_k2.unseal(cert.stored_key_encrypted_pem, aad_for(CERT_KEY_TABLE, cert.id, CERT_KEY_COLUMN))
                == b"cert-key"
            )


def test_kek_rewrap_unknown_target_exits_2(db_session, SessionLocal, capsys):
    _seed(db_session)
    before = _values(db_session)

    code = cli.main(["kek", "rewrap", "--to", "nope"], session_factory=SessionLocal, keyring=_ring())

    captured = capsys.readouterr()
    assert code == 2
    assert captured.err.strip() == "error: KEK 'nope' is not loaded"
    assert captured.out == ""
    assert _values(db_session) == before


def test_kek_rewrap_is_atomic_on_failure(db_session, SessionLocal, capsys):
    _seed(db_session)
    victim = _add_cert(db_session, "k1", "cert-wrong-aad", aad_id="some-other-row")
    before = _values(db_session)

    code = cli.main(["kek", "rewrap", "--to", "k2"], session_factory=SessionLocal, keyring=_ring())

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err.strip() == f"error: rewrap failed for certificates {victim.id}: IntegrityError"
    assert _values(db_session) == before
    assert _rewrap_audits(db_session) == []


def test_kek_rewrap_refuses_legacy_values(db_session, SessionLocal, capsys):
    _seed(db_session)
    _add_cert(db_session, None, "cert-legacy", raw="enc::" + base64.b64encode(b"old").decode())
    before = _values(db_session)

    code = cli.main(["kek", "rewrap", "--to", "k2"], session_factory=SessionLocal, keyring=_ring())

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.strip() == "error: legacy enc:: values present; run 'alembic upgrade head' first"
    assert _values(db_session) == before
    assert _rewrap_audits(db_session) == []


def test_kek_rewrap_malformed_value_fails_cleanly(db_session, SessionLocal, capsys):
    _seed(db_session)
    bad = _add_cert(db_session, None, "cert-bad", raw="garbage")
    before = _values(db_session)

    code = cli.main(["kek", "rewrap", "--to", "k2"], session_factory=SessionLocal, keyring=_ring())

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.strip() == f"error: rewrap failed for certificates {bad.id}: MalformedTokenError"
    assert _values(db_session) == before


def test_default_keyring_failure_is_reported(db_session, SessionLocal, capsys, monkeypatch, tmp_path):
    from app.config import get_settings
    from app.services import keystore

    monkeypatch.setenv("LABCA_KEK_DIR", str(tmp_path / "missing"))
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()

    code = cli.main(["kek", "status"], session_factory=SessionLocal)

    captured = capsys.readouterr()
    assert code == 1
    assert captured.err.startswith("error: ")
    assert captured.out == ""


def test_default_keyring_and_session_factory(db_session, capsys, monkeypatch):
    # With no overrides, main() falls back to the cached keyring and app.db.SessionLocal.
    import app.db

    class _Empty:
        def __call__(self):
            return db_session

    monkeypatch.setattr(app.db, "SessionLocal", _Empty())
    code = cli.main(["kek", "status"])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["active_kek_id"] == "test-1"
    assert report["loaded_kek_ids"] == ["test-1"]
