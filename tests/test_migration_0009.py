"""Tests for the 20261014_0009 Alembic revision."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect

from alembic import command
from alembic.config import Config
from app.config import get_settings
from app.services import keystore

REPO_ROOT = Path(__file__).resolve().parent.parent
PRE_REVISION = "20261014_0008"
REVISION = "20261014_0009"  # the revision under test, not head, so later migrations do not change this test


def _alembic_config(tmp_path: Path, monkeypatch) -> tuple[Config, str]:
    url = f"sqlite:///{tmp_path / 'migrate0009.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()
    cfg = Config()  # no file name, so env.py never calls fileConfig and logging stays untouched
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    return cfg, url


def _tables(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def _unique_on_ca_id(url: str) -> bool:
    engine = create_engine(url)
    try:
        inspector = inspect(engine)
        constraints = inspector.get_unique_constraints("crls")
        indexes = inspector.get_indexes("crls")
        return any(c["column_names"] == ["ca_id"] for c in constraints) or any(
            i["column_names"] == ["ca_id"] and i["unique"] for i in indexes
        )
    finally:
        engine.dispose()


def test_upgrade_creates_crls_with_unique_ca_id(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, PRE_REVISION)
    assert "crls" not in _tables(url)

    command.upgrade(cfg, REVISION)

    assert "crls" in _tables(url)
    engine = create_engine(url)
    try:
        columns = {column["name"] for column in inspect(engine).get_columns("crls")}
        foreign_keys = inspect(engine).get_foreign_keys("crls")
    finally:
        engine.dispose()
    assert columns == {
        "id",
        "ca_id",
        "crl_number",
        "this_update",
        "next_update",
        "generated_at",
        "revoked_count",
        "der",
        "created_at",
        "updated_at",
    }
    assert _unique_on_ca_id(url)
    assert foreign_keys[0]["referred_table"] == "certificate_authorities"
    assert foreign_keys[0]["options"].get("ondelete") == "CASCADE"


def test_downgrade_removes_table_and_upgrade_again(tmp_path, monkeypatch):
    cfg, url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(cfg, REVISION)

    command.downgrade(cfg, PRE_REVISION)
    assert "crls" not in _tables(url)

    command.upgrade(cfg, REVISION)
    assert "crls" in _tables(url)
