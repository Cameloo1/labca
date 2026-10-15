"""Tests for ``python -m app.cli backup`` and ``verify-db``."""

from __future__ import annotations

import os
import sqlite3
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import cli
from app.config import get_settings
from app.models import Base, CASourceTypeEnum, CAStatusEnum, CertificateAuthority
from app.services import keystore
from app.services.keystore import KeyRing
from tests.cli_support import cert_pem, key_pem, run, run_json, self_signed

RING = KeyRing({"k1": bytes(range(32, 64))}, active_kek_id="k1")


def _add_ca(session: Session, name: str, *, sealed: bool = True) -> CertificateAuthority:
    cert, key = self_signed(name, ca=True)
    ca_id = str(uuid.uuid4())
    token = None
    if sealed:
        token = RING.seal(key_pem(key), keystore.aad_for(keystore.CA_KEY_TABLE, ca_id, keystore.CA_KEY_COLUMN))
    ca = CertificateAuthority(
        id=ca_id,
        name=name,
        source_type=CASourceTypeEnum.ROOT,
        subject_cn=name,
        subject_json={},
        serial_number=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_algorithm="ECDSA",
        key_size=256,
        status=CAStatusEnum.ACTIVE,
        cert_pem=cert_pem(cert).decode(),
        key_encrypted_pem=token,
    )
    session.add(ca)
    session.commit()
    return ca


@pytest.fixture
def file_db(tmp_path, monkeypatch) -> Path:
    """A file SQLite database with the schema, pointed at by DATABASE_URL."""
    path = tmp_path / "data" / "labca.db"
    path.parent.mkdir()
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        _add_ca(session, "CA One")
        _add_ca(session, "CA Two")
        _add_ca(session, "Keyless", sealed=False)
    engine.dispose()
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{path}")
    get_settings.cache_clear()
    return path


def _open(path: Path) -> Session:
    return Session(create_engine(f"sqlite:///{path}"))


def _counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        return {
            t: conn.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0] for t in tables
        }  # names come from sqlite_master
    finally:
        conn.close()


@pytest.fixture
def clock(monkeypatch):
    """Make backup names distinct without sleeping: each call is one second later."""
    state = {"now": datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)}

    def tick() -> datetime:
        state["now"] += timedelta(seconds=1)
        return state["now"]

    monkeypatch.setattr(cli, "_utcnow", tick)


# --- backup -----------------------------------------------------------------------------


def test_backup_happy_path(capsys, file_db, tmp_path, clock):
    out_dir = tmp_path / "bk"
    code, result = run_json(capsys, ["backup", "--out-dir", str(out_dir), "--keep", "3"])
    assert code == 0
    assert set(result) == {"backup", "size_bytes", "integrity", "pruned"}
    assert result["integrity"] == "ok"
    assert result["pruned"] == []
    backup = Path(result["backup"])
    assert backup.parent == out_dir
    assert backup.name == "labca-20261015T120001Z.db"
    assert result["size_bytes"] == backup.stat().st_size > 0
    if os.name != "nt":
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600
        assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700
    assert list(out_dir.glob("*.partial")) == []
    assert _counts(backup) == _counts(file_db)
    assert b"PRIVATE KEY" not in backup.read_bytes()
    with _open(backup) as session:
        assert len(session.scalars(select(CertificateAuthority)).all()) == 3


def test_backup_keep_prunes_oldest_and_ignores_other_files(capsys, file_db, tmp_path, clock):
    out_dir = tmp_path / "bk"
    out_dir.mkdir()
    (out_dir / "notes.txt").write_text("keep me")
    (out_dir / "other.db").write_text("not a labca backup")
    results = [run_json(capsys, ["backup", "--out-dir", str(out_dir), "--keep", "2"])[1] for _ in range(3)]
    kept = sorted(p.name for p in out_dir.glob("labca-*.db"))
    assert kept == [Path(results[1]["backup"]).name, Path(results[2]["backup"]).name]
    assert results[2]["pruned"] == [Path(results[0]["backup"]).name]
    assert (out_dir / "notes.txt").read_text() == "keep me"
    assert (out_dir / "other.db").read_text() == "not a labca backup"


@pytest.mark.parametrize("url", ["postgresql://u@h/db", "sqlite:///:memory:"])
def test_backup_rejects_unsupported_database(capsys, monkeypatch, tmp_path, url):
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    code, out, err = run(capsys, ["backup", "--out-dir", str(tmp_path / "bk"), "--keep", "2"])
    assert code == 2
    assert out == ""
    assert err.strip() == "error: backup supports file-based SQLite only"
    assert not (tmp_path / "bk").exists()


def test_backup_rejects_keep_below_one(capsys, file_db, tmp_path):
    code, _out, err = run(capsys, ["backup", "--out-dir", str(tmp_path / "bk"), "--keep", "0"])
    assert code == 2
    assert "--keep" in err


def test_backup_missing_database_file(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'absent.db'}")
    get_settings.cache_clear()
    code, _out, err = run(capsys, ["backup", "--out-dir", str(tmp_path / "bk"), "--keep", "1"])
    assert code == 1
    assert err.strip() == "error: database file not found"
    assert not (tmp_path / "absent.db").exists()


def test_backup_failed_integrity_check_leaves_nothing(capsys, monkeypatch, file_db, tmp_path, clock):
    monkeypatch.setattr(cli, "_integrity_result", lambda _path: "row 1 missing from index")
    out_dir = tmp_path / "bk"
    code, _out, err = run(capsys, ["backup", "--out-dir", str(out_dir), "--keep", "2"])
    assert code == 1
    assert "integrity" in err
    assert list(out_dir.iterdir()) == []


# --- verify-db --------------------------------------------------------------------------


def test_verify_db_good(capsys, file_db):
    before = file_db.read_bytes()
    code, result = run_json(capsys, ["verify-db", "--db", str(file_db)], keyring=RING)
    assert code == 0
    assert result == {"integrity": "ok", "cas_checked": 2, "failures": []}
    assert file_db.read_bytes() == before


def test_verify_db_swapped_sealed_keys_fail_to_unseal(capsys, file_db):
    with _open(file_db) as session:
        one, two = session.scalars(
            select(CertificateAuthority).where(CertificateAuthority.key_encrypted_pem.is_not(None))
        ).all()
        one.key_encrypted_pem, two.key_encrypted_pem = two.key_encrypted_pem, one.key_encrypted_pem
        session.commit()
        ids = {one.id, two.id}
    code, result = run_json(capsys, ["verify-db", "--db", str(file_db)], keyring=RING)
    assert code == 1
    assert {f["ca_id"] for f in result["failures"]} == ids
    assert {f["reason"] for f in result["failures"]} == {"unseal_failed"}
    assert result["cas_checked"] == 2


def test_verify_db_replaced_certificate_is_key_mismatch(capsys, file_db):
    other, _key = self_signed("Impostor", ca=True)
    with _open(file_db) as session:
        ca = session.scalars(select(CertificateAuthority).where(CertificateAuthority.name == "CA One")).one()
        ca.cert_pem = cert_pem(other).decode()
        session.commit()
        target = ca.id
    code, result = run_json(capsys, ["verify-db", "--db", str(file_db)], keyring=RING)
    assert code == 1
    assert result["failures"] == [{"ca_id": target, "reason": "key_mismatch"}]


def test_verify_db_unparseable_key_and_certificate(capsys, file_db):
    with _open(file_db) as session:
        one = session.scalars(select(CertificateAuthority).where(CertificateAuthority.name == "CA One")).one()
        two = session.scalars(select(CertificateAuthority).where(CertificateAuthority.name == "CA Two")).one()
        one.key_encrypted_pem = RING.seal(
            b"junk", keystore.aad_for(keystore.CA_KEY_TABLE, one.id, keystore.CA_KEY_COLUMN)
        )
        two.cert_pem = "not a certificate"
        session.commit()
        ids = (one.id, two.id)
    code, result = run_json(capsys, ["verify-db", "--db", str(file_db)], keyring=RING)
    assert code == 1
    assert {(f["ca_id"], f["reason"]) for f in result["failures"]} == {
        (ids[0], "key_unparseable"),
        (ids[1], "cert_unparseable"),
    }


def test_verify_db_wrong_keyring_fails_to_unseal(capsys, file_db):
    other = KeyRing({"k9": bytes(range(64, 96))}, active_kek_id="k9")
    code, result = run_json(capsys, ["verify-db", "--db", str(file_db)], keyring=other)
    assert code == 1
    assert {f["reason"] for f in result["failures"]} == {"unseal_failed"}


def test_verify_db_missing_file(capsys, tmp_path):
    code, out, err = run(capsys, ["verify-db", "--db", str(tmp_path / "nope.db")], keyring=RING)
    assert code == 1
    assert out == ""
    assert err.startswith("error:")


def test_verify_db_not_a_database(capsys, tmp_path):
    bogus = tmp_path / "bogus.db"
    bogus.write_bytes(b"this is not a sqlite database" * 100)
    code, out, err = run(capsys, ["verify-db", "--db", str(bogus)], keyring=RING)
    assert code == 1
    assert out == ""
    assert "database could not be read" in err


def test_verify_db_reports_failed_integrity(capsys, monkeypatch, file_db):
    class FakeResult:
        def fetchall(self):
            return [("*** in database main ***\nPage 2: never used",)]

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def exec_driver_sql(self, _statement):
            return FakeResult()

    class FakeEngine:
        def connect(self):
            return FakeConn()

        def dispose(self):
            pass

    monkeypatch.setattr(cli, "create_engine", lambda *_a, **_k: FakeEngine())
    code, result = run_json(capsys, ["verify-db", "--db", str(file_db)], keyring=RING)
    assert code == 1
    assert result == {"integrity": "*** in database main ***", "cas_checked": 0, "failures": []}


def test_private_key_pem_never_printed(capsys, file_db):
    _code, out, err = run(capsys, ["verify-db", "--db", str(file_db)], keyring=RING)
    assert "PRIVATE KEY" not in out + err
    assert "labca:v1:" not in out + err
