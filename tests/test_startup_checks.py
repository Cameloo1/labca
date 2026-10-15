"""Tests for the startup checks and the application lifespan."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.main import app
from app.services import keystore
from app.services.keystore import KeyRing
from app.startup import StartupCheckError, run_startup_checks

KEK = bytes(range(32))


def _settings(**values) -> Settings:
    defaults = {"ENV": "dev", "LABCA_KEK_DIR": "", "LABCA_ACTIVE_KEK_ID": ""}
    return Settings(_env_file=None, **{**defaults, **values})


def _reset_caches() -> None:
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()


def test_prod_refuses_empty_keyring():
    with pytest.raises(StartupCheckError, match="no KEK is loaded"):
        run_startup_checks(_settings(ENV="prod"), KeyRing({}))


def test_prod_refuses_missing_active_kek():
    with pytest.raises(StartupCheckError, match="LABCA_ACTIVE_KEK_ID is not set"):
        run_startup_checks(_settings(ENV="prod"), KeyRing({"k1": KEK}))


def test_prod_refuses_unloaded_active_kek():
    with pytest.raises(StartupCheckError, match="active KEK 'ghost' is not loaded"):
        run_startup_checks(_settings(ENV="prod"), KeyRing({"k1": KEK}, active_kek_id="ghost"))


def test_prod_collects_all_problems():
    with pytest.raises(StartupCheckError) as info:
        run_startup_checks(_settings(ENV="prod"), KeyRing({}))
    message = str(info.value)
    assert message.startswith("Refusing to start with ENV=prod: ")
    assert "no KEK is loaded" in message
    assert "LABCA_ACTIVE_KEK_ID is not set" in message


def test_prod_refuses_env_keks(monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    _reset_caches()
    with pytest.raises(StartupCheckError, match="environment variables"):
        run_startup_checks(get_settings())


def test_prod_accepts_kek_dir(monkeypatch, tmp_path):
    (tmp_path / "prod-1").write_text(base64.b64encode(KEK).decode())
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.setenv("LABCA_KEK_DIR", str(tmp_path))
    monkeypatch.setenv("LABCA_ACTIVE_KEK_ID", "prod-1")
    monkeypatch.setenv("ADMIN_AUTH_MODE", "localhost_only")  # prod refuses ADMIN_AUTH_MODE=none
    # the other prod startup rules need safe values too
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    monkeypatch.setenv("ENABLE_API_DOCS", "false")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://labca.example.test")
    monkeypatch.setenv("DATABASE_URL", "sqlite:////data/labca.db")
    monkeypatch.delenv("LABCA_KEK_TEST_1")
    _reset_caches()
    run_startup_checks(get_settings())


def test_bad_keyring_config_is_wrapped_in_every_env(monkeypatch, tmp_path):
    monkeypatch.setenv("LABCA_KEK_DIR", str(tmp_path / "missing"))
    _reset_caches()
    with pytest.raises(StartupCheckError, match="Keyring configuration error"):
        run_startup_checks(get_settings())


def test_dev_allows_empty_keyring():
    run_startup_checks(_settings(ENV="dev"), KeyRing({}))


def test_lifespan_refuses_prod_without_kek(monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.delenv("LABCA_KEK_TEST_1")
    monkeypatch.delenv("LABCA_ACTIVE_KEK_ID")
    _reset_caches()
    with pytest.raises(StartupCheckError):
        with TestClient(app):
            pass


def test_lifespan_starts_in_dev():
    with TestClient(app) as test_client:
        assert test_client.get("/health").json() == {"status": "ok"}
