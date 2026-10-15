"""Tests for the 20261014_0008 Alembic revision."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect, text

from alembic import command
from alembic.config import Config
from app.config import get_settings
from app.services import keystore

REPO_ROOT = Path(__file__).resolve().parent.parent
PRE_REVISION = "20261014_0007"
REVISION = "20261014_0008"  # the revision under test, not head, so later migrations do not change this test


def _alembic_config(tmp_path: Path, monkeypatch) -> tuple[Config, str]:
    url = f"sqlite:///{tmp_path / 'migrate0008.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()
    cfg = Config()  # no file name, so env.py never calls fileConfig and logging stays untouched
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    return cfg, url


def _insert_certificate(url: str) -> None:
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO certificates (id, ca_id, type, common_name, san_dns, san_ips, serial_number, "
                "not_before, not_after, key_algorithm, key_size, status, environment_tags, "
                "stored_key_encrypted_pem, cert_pem, is_ephemeral) VALUES ('c1', NULL, 'LEAF', 'leaf', '[]', "
                "'[]', 'serial-1', '2026-01-01 00:00:00', '2030-01-01 00:00:00', 'RSA', 2048, 'ACTIVE', "
                "'[]', NULL, 'PEM', 0)"
            )
        )
    engine.dispose()


def _columns(url: str, table: str) -> set[str]:
    engine = create_engine(url)
    try:
        return {column["name"] for column in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


def _index_names(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return {index["name"] for index in inspect(engine).get_indexes("certificates")}
    finally:
        engine.dispose()


def test_upgrade_adds_columns_and_defaults_existing_rows(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, PRE_REVISION)
    _insert_certificate(url)

    command.upgrade(cfg, REVISION)

    assert {"san_uris", "issued_by_token_id", "revocation_reason_code"} <= _columns(url, "certificates")
    assert "policy_json" in _columns(url, "api_tokens")
    assert "ix_certificates_issued_by_token_id" in _index_names(url)
    engine = create_engine(url)
    with engine.connect() as conn:
        row = conn.execute(text("SELECT san_uris, issued_by_token_id, revocation_reason_code FROM certificates")).one()
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    engine.dispose()
    assert row[0] == "[]"
    assert row[1] is None and row[2] is None
    assert version == REVISION


def test_downgrade_then_upgrade_again(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, PRE_REVISION)
    _insert_certificate(url)
    command.upgrade(cfg, REVISION)

    command.downgrade(cfg, PRE_REVISION)

    assert not {"san_uris", "issued_by_token_id", "revocation_reason_code"} & _columns(url, "certificates")
    assert "policy_json" not in _columns(url, "api_tokens")
    assert "ix_certificates_issued_by_token_id" not in _index_names(url)

    command.upgrade(cfg, REVISION)

    assert "san_uris" in _columns(url, "certificates")
    engine = create_engine(url)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM certificates")).scalar_one() == 1
        assert conn.execute(text("SELECT san_uris FROM certificates")).scalar_one() == "[]"
    engine.dispose()
