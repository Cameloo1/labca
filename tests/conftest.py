"""Pytest configuration and shared fixtures for LabCA test suite."""

from __future__ import annotations

import base64
import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.dependencies import get_db
from app.main import app
from app.models import Base
from app.services import keystore
from app.services.revocation_service import restore_post_revoke_hooks, snapshot_post_revoke_hooks
from app.services.tokenreview import get_token_reviewer
from app.services.workload_service import reset_rate_limiter


@pytest.fixture(scope="function", autouse=True)
def settings_override(monkeypatch) -> Generator[None, None, None]:
    """Override settings to use test database."""
    # Set environment variables before clearing cache
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("API_TOKEN_CREATION_SECRET", "unit-secret")

    # Start from a clean keystore environment, then configure one deterministic test KEK.
    for name in list(os.environ):
        if name.startswith("LABCA_KEK_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("LABCA_ACTIVE_KEK_ID", raising=False)
    monkeypatch.setenv("LABCA_KEK_TEST_1", base64.b64encode(bytes(range(32))).decode())
    monkeypatch.setenv("LABCA_ACTIVE_KEK_ID", "test-1")

    # Clear the cache to get fresh settings
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()

    yield

    # Clear cache again to ensure fresh settings on next call
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()


@pytest.fixture(scope="function")
def engine(settings_override):
    """Create a test database engine."""
    settings = get_settings()
    test_engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {},
        poolclass=StaticPool,
    )
    return test_engine


@pytest.fixture(scope="function")
def SessionLocal(engine):
    """Create a session factory bound to the test engine."""
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session(engine, SessionLocal) -> Generator[Session, None, None]:
    """Create database tables, yield a session, then drop tables."""
    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Create a session
    session = SessionLocal()

    try:
        yield session
    finally:
        session.close()
        # Drop all tables
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session, settings_override) -> Generator[TestClient, None, None]:
    """Create a FastAPI TestClient with database dependency override."""
    # Ensure settings cache is cleared so routes get the updated settings
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass  # Don't close the session here, it's managed by db_session fixture

    app.dependency_overrides[get_db] = override_get_db

    test_client = TestClient(app, raise_server_exceptions=False)

    yield test_client

    # Clean up
    app.dependency_overrides.clear()


@pytest.fixture(scope="function", autouse=True)
def _restore_post_revoke_hooks() -> Generator[None, None, None]:
    """Keep tests that clear or add post-revocation hooks from leaking into other tests."""
    snapshot = snapshot_post_revoke_hooks()
    yield
    restore_post_revoke_hooks(snapshot)


@pytest.fixture(scope="function", autouse=True)
def _reset_workload_state() -> Generator[None, None, None]:
    """Start each test with a fresh workload rate limiter and token reviewer."""
    reset_rate_limiter()
    get_token_reviewer.cache_clear()
    yield
