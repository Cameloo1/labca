"""Tests for GET /ready and app.readiness.readiness_reasons."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Iterator, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app import readiness
from app.config import Settings, get_settings
from app.dependencies import get_db
from app.main import app
from app.services import keystore
from app.services.keystore import KeyRing

REPO_ROOT = Path(__file__).resolve().parent.parent
KEK = bytes(range(32))


def _settings(**values) -> Settings:
    defaults = {"ENV": "dev", "LABCA_KEK_DIR": "", "LABCA_ACTIVE_KEK_ID": "k1"}
    return Settings(_env_file=None, **{**defaults, **values})


def _ring() -> KeyRing:
    return KeyRing({"k1": KEK}, active_kek_id="k1")


@pytest.fixture
def migrated_db(tmp_path, monkeypatch) -> Iterator[Session]:
    """A file database upgraded to the alembic head by the real migrations."""
    path = tmp_path / "ready.db"
    url = f"sqlite:///{path}"
    monkeypatch.setenv("DATABASE_URL", url)
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-500:]
    engine = create_engine(url)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _client_for(session) -> TestClient:
    def override():
        yield session

    app.dependency_overrides[get_db] = override
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


class BrokenSession:
    def execute(self, *_args, **_kwargs):
        raise RuntimeError("secret-boom /var/lib/secret-path")

    def connection(self):
        raise RuntimeError("secret-boom /var/lib/secret-path")


# --- readiness_reasons ------------------------------------------------------------------


def test_ready_when_everything_is_in_place(migrated_db):
    assert readiness.readiness_reasons(migrated_db, _settings(), _ring()) == []


def test_missing_alembic_version_is_not_at_head(db_session):
    reasons = readiness.readiness_reasons(db_session, _settings(), _ring())
    assert reasons == ["migrations_not_at_head"]


def test_empty_keyring(migrated_db):
    reasons = readiness.readiness_reasons(migrated_db, _settings(), KeyRing({}))
    assert "keyring_empty" in reasons
    assert "database_unreachable" not in reasons


def test_missing_keyring_object_counts_as_empty(migrated_db):
    assert "keyring_empty" in readiness.readiness_reasons(migrated_db, _settings(), None)


def test_active_kek_not_loaded(migrated_db):
    reasons = readiness.readiness_reasons(migrated_db, _settings(LABCA_ACTIVE_KEK_ID="ghost"), _ring())
    assert reasons == ["active_kek_missing"]


def test_active_kek_unset(migrated_db):
    reasons = readiness.readiness_reasons(migrated_db, _settings(LABCA_ACTIVE_KEK_ID=""), _ring())
    assert reasons == ["active_kek_missing"]


def test_workload_issuer_missing(migrated_db):
    settings = _settings(WORKLOAD_ISSUANCE_ENABLED=True, WORKLOAD_ISSUER_CA_NAME="Nope")
    assert readiness.readiness_reasons(migrated_db, settings, _ring()) == ["workload_issuer_missing"]


def test_workload_check_skipped_when_disabled(migrated_db):
    settings = _settings(WORKLOAD_ISSUANCE_ENABLED=False, WORKLOAD_ISSUER_CA_NAME="Nope")
    assert readiness.readiness_reasons(migrated_db, settings, _ring()) == []


def test_broken_session_reports_only_database_unreachable():
    settings = _settings(WORKLOAD_ISSUANCE_ENABLED=True)
    assert readiness.readiness_reasons(cast(Session, BrokenSession()), settings, _ring()) == ["database_unreachable"]


# --- endpoint ---------------------------------------------------------------------------


def test_ready_endpoint_200(migrated_db, monkeypatch):
    monkeypatch.setenv("LABCA_ACTIVE_KEK_ID", "test-1")
    get_settings.cache_clear()
    response = _client_for(migrated_db).get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert response.headers["cache-control"] == "no-store"


def test_ready_endpoint_503_without_migrations(db_session):
    response = _client_for(db_session).get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "reasons": ["migrations_not_at_head"]}
    assert response.headers["cache-control"] == "no-store"


def test_ready_endpoint_keyring_load_error_counts_as_empty(migrated_db, monkeypatch):
    monkeypatch.setenv("LABCA_KEK_DIR", "/secret/kek-dir/missing")
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()
    with pytest.raises(keystore.KeyringConfigError):
        keystore.get_keyring()
    response = _client_for(migrated_db).get("/ready")
    assert response.status_code == 503
    assert "keyring_empty" in response.json()["reasons"]
    assert "/secret/kek-dir" not in response.text


def test_ready_endpoint_never_leaks_exception_text():
    response = _client_for(BrokenSession()).get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "reasons": ["database_unreachable"]}
    assert "secret-boom" not in response.text
    assert "secret-path" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_ready_needs_no_auth_in_localhost_only_mode(db_session, monkeypatch):
    monkeypatch.setenv("ADMIN_AUTH_MODE", "localhost_only")
    get_settings.cache_clear()
    client = _client_for(db_session)
    assert client.get("/ready").status_code in (200, 503)
    assert client.get("/health").status_code == 200
    # an admin route from the same non-local client is refused, proving the mode is active
    assert client.get("/audit").status_code in (401, 403)
