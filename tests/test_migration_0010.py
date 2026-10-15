"""Tests for the 20261014_0010 Alembic revision."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect, text

from alembic import command
from alembic.config import Config
from app.config import get_settings
from app.services import keystore

REPO_ROOT = Path(__file__).resolve().parent.parent
PRE_REVISION = "20261014_0009"
REVISION = "20261014_0010"  # the revision under test, not head, so later migrations do not change this test
INDEX = "ix_certificates_issued_to_spiffe_id"


def _alembic_config(tmp_path: Path, monkeypatch) -> tuple[Config, str]:
    url = f"sqlite:///{tmp_path / 'migrate0010.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()
    cfg = Config()  # no file name, so env.py never calls fileConfig and logging stays untouched
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    return cfg, url


def _columns(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return {column["name"] for column in inspect(engine).get_columns("certificates")}
    finally:
        engine.dispose()


def _indexes(url: str) -> dict[str, list[str]]:
    engine = create_engine(url)
    try:
        return {index["name"]: list(index["column_names"]) for index in inspect(engine).get_indexes("certificates")}
    finally:
        engine.dispose()


def test_upgrade_adds_column_and_index(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, PRE_REVISION)
    assert "issued_to_spiffe_id" not in _columns(url)

    command.upgrade(cfg, REVISION)

    assert "issued_to_spiffe_id" in _columns(url)
    assert _indexes(url)[INDEX] == ["issued_to_spiffe_id"]


def test_audit_row_with_workload_actor_inserts_after_upgrade(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, REVISION)

    engine = create_engine(url)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO audit_logs (id, timestamp, actor_type, actor_id, action, target_type, "
                    "target_id, status, ip_address, details_json) VALUES ('a1', '2026-10-14 00:00:00', "
                    "'WORKLOAD', 'spiffe://labca.example.test/ns/mtls-demo/sa/demo-client', 'WORKLOAD_SIGN', "
                    "'certificate', NULL, 'SUCCESS', '127.0.0.1', '{}')"
                )
            )
            actor = conn.execute(text("SELECT actor_type FROM audit_logs WHERE id = 'a1'")).scalar_one()
    finally:
        engine.dispose()
    assert actor == "WORKLOAD"


def test_downgrade_removes_column_and_upgrade_again(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, REVISION)

    command.downgrade(cfg, PRE_REVISION)
    assert "issued_to_spiffe_id" not in _columns(url)
    assert INDEX not in _indexes(url)

    command.upgrade(cfg, REVISION)
    assert "issued_to_spiffe_id" in _columns(url)
    assert INDEX in _indexes(url)
