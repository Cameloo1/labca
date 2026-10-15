"""Tests for the legacy enc:: conversion and its Alembic revision."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from alembic import command
from alembic.config import Config
from app.config import get_settings
from app.services import keystore
from app.services.keystore import KeyRing, aad_for
from app.services.keystore_migration import convert_legacy_values

REPO_ROOT = Path(__file__).resolve().parent.parent
PRE_REVISION = "20251201_0006"
HEAD_REVISION = "20261014_0007"
CA_ID = "11111111-1111-1111-1111-111111111111"
CERT_ID = "22222222-2222-2222-2222-222222222222"
CA_PLAINTEXT = b"legacy-ca-key"
CERT_PLAINTEXT = b"legacy-cert-key"


def _legacy(plaintext: bytes) -> str:
    return "enc::" + base64.b64encode(plaintext).decode()


def _alembic_config(tmp_path: Path, monkeypatch) -> tuple[Config, str]:
    url = f"sqlite:///{tmp_path / 'migrate.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()
    cfg = Config()  # no file name, so env.py never calls fileConfig and logging stays untouched
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    return cfg, url


def _insert_legacy_rows(url: str) -> None:
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO certificate_authorities (id, name, source_type, subject_cn, subject_json, "
                "serial_number, not_before, not_after, key_algorithm, key_size, status, cert_pem, "
                "key_encrypted_pem) VALUES (:id, 'CA', 'ROOT', 'CA', '{}', 'ca-serial', "
                "'2026-01-01 00:00:00', '2030-01-01 00:00:00', 'RSA', 2048, 'ACTIVE', 'PEM', :key)"
            ),
            {"id": CA_ID, "key": _legacy(CA_PLAINTEXT)},
        )
        conn.execute(
            text(
                "INSERT INTO certificates (id, ca_id, type, common_name, san_dns, san_ips, serial_number, "
                "not_before, not_after, key_algorithm, key_size, status, environment_tags, "
                "stored_key_encrypted_pem, cert_pem, is_ephemeral) VALUES (:id, :ca, 'LEAF', 'leaf', '[]', "
                "'[]', 'cert-serial', '2026-01-01 00:00:00', '2030-01-01 00:00:00', 'RSA', 2048, 'ACTIVE', "
                "'[]', :key, 'PEM', 0)"
            ),
            {"id": CERT_ID, "ca": CA_ID, "key": _legacy(CERT_PLAINTEXT)},
        )
    engine.dispose()


def _read_values(url: str) -> tuple[str, str, str]:
    engine = create_engine(url)
    with engine.connect() as conn:
        ca_value = conn.execute(text("SELECT key_encrypted_pem FROM certificate_authorities")).scalar_one()
        cert_value = conn.execute(text("SELECT stored_key_encrypted_pem FROM certificates")).scalar_one()
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    engine.dispose()
    return ca_value, cert_value, version


def test_upgrade_converts_legacy_values(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, PRE_REVISION)
    _insert_legacy_rows(url)

    command.upgrade(cfg, "head")

    ca_value, cert_value, version = _read_values(url)
    assert ca_value.startswith("labca:v1:test-1:")
    assert cert_value.startswith("labca:v1:test-1:")
    assert keystore.unseal_ca_key(CA_ID, ca_value) == CA_PLAINTEXT
    assert keystore.unseal_cert_key(CERT_ID, cert_value) == CERT_PLAINTEXT
    assert version == HEAD_REVISION


def test_upgrade_fails_loudly_without_kek(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, PRE_REVISION)
    _insert_legacy_rows(url)
    monkeypatch.delenv("LABCA_KEK_TEST_1")
    monkeypatch.delenv("LABCA_ACTIVE_KEK_ID")
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()

    with pytest.raises(RuntimeError, match="no active KEK"):
        command.upgrade(cfg, "head")

    ca_value, cert_value, version = _read_values(url)
    assert ca_value.startswith("enc::")
    assert cert_value.startswith("enc::")
    assert version == PRE_REVISION


def test_upgrade_empty_db_without_kek_succeeds(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    monkeypatch.delenv("LABCA_KEK_TEST_1")
    monkeypatch.delenv("LABCA_ACTIVE_KEK_ID")
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()

    command.upgrade(cfg, "head")

    engine = create_engine(url)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == HEAD_REVISION
    engine.dispose()


def test_convert_legacy_values_is_idempotent(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, PRE_REVISION)
    _insert_legacy_rows(url)
    ring = KeyRing({"k1": bytes(range(32))}, active_kek_id="k1")
    engine = create_engine(url)
    with engine.begin() as conn:
        first = convert_legacy_values(conn, ring)
    assert first == {"certificate_authorities.key_encrypted_pem": 1, "certificates.stored_key_encrypted_pem": 1}
    with engine.begin() as conn:
        before = conn.execute(text("SELECT key_encrypted_pem FROM certificate_authorities")).scalar_one()
        second = convert_legacy_values(conn, ring)
        after = conn.execute(text("SELECT key_encrypted_pem FROM certificate_authorities")).scalar_one()
    engine.dispose()
    assert second == {"certificate_authorities.key_encrypted_pem": 0, "certificates.stored_key_encrypted_pem": 0}
    assert before == after
    assert ring.unseal(after, aad_for("certificate_authorities", CA_ID, "key_encrypted_pem")) == CA_PLAINTEXT


def test_convert_rejects_invalid_base64_without_changes(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, PRE_REVISION)
    _insert_legacy_rows(url)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("UPDATE certificates SET stored_key_encrypted_pem = 'enc::***'"))
    ring = KeyRing({"k1": bytes(range(32))}, active_kek_id="k1")
    with engine.begin() as conn:
        with pytest.raises(RuntimeError, match=CERT_ID):
            convert_legacy_values(conn, ring)
    with engine.connect() as conn:
        value = conn.execute(text("SELECT key_encrypted_pem FROM certificate_authorities")).scalar_one()
    engine.dispose()
    assert value.startswith("enc::")


def test_downgrade_is_refused(tmp_path, monkeypatch):
    cfg, _url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, "head")

    with pytest.raises(NotImplementedError, match="plaintext"):
        command.downgrade(cfg, PRE_REVISION)
