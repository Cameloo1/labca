"""Tests for the prod startup validation rules."""

from __future__ import annotations

import logging

import pytest

from app.config import Settings
from app.services.keystore import KeyRing
from app.startup import StartupCheckError, run_startup_checks

KEK = bytes(range(32))
DISTINCT_SECRET = "short-but-distinctive-secret-value"  # 34 chars: long enough on its own


def _ring() -> KeyRing:
    return KeyRing({"k1": KEK}, active_kek_id="k1")


def _prod(**overrides) -> Settings:
    values = {
        "ENV": "prod",
        "LABCA_KEK_DIR": "",
        "LABCA_ACTIVE_KEK_ID": "",
        "SECRET_KEY": "s" * 40,
        "ENABLE_API_DOCS": False,
        "ADMIN_AUTH_MODE": "localhost_only",
        "PUBLIC_BASE_URL": "https://labca.example.test",
        "DATABASE_URL": "sqlite:////data/labca.db",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_fully_valid_prod_settings_pass():
    run_startup_checks(_prod(), _ring())


def test_valid_prod_with_workload_settings_passes():
    settings = _prod(WORKLOAD_ISSUANCE_ENABLED=True, WORKLOAD_TRUST_DOMAIN="labca.example.test")
    with pytest.raises(StartupCheckError, match="WORKLOAD_ISSUER_CA_NAME"):
        run_startup_checks(settings, _ring())
    ok = _prod(
        WORKLOAD_ISSUANCE_ENABLED=True, WORKLOAD_TRUST_DOMAIN="labca.example.test", WORKLOAD_ISSUER_CA_NAME="Issuing"
    )
    run_startup_checks(ok, _ring())


@pytest.mark.parametrize(
    ("overrides", "ring", "expected"),
    [
        ({"SECRET_KEY": "CHANGE_ME"}, _ring(), "SECRET_KEY"),
        ({"SECRET_KEY": "x" * 31}, _ring(), "SECRET_KEY"),
        ({"ENABLE_API_DOCS": True}, _ring(), "ENABLE_API_DOCS"),
        ({"ADMIN_AUTH_MODE": "none"}, _ring(), "ADMIN_AUTH_MODE=none is not allowed in prod."),
        ({}, KeyRing({}), "no KEK is loaded"),
        ({}, KeyRing({"k1": KEK}), "LABCA_ACTIVE_KEK_ID is not set"),
        ({"PUBLIC_BASE_URL": None}, _ring(), "PUBLIC_BASE_URL"),
        ({"PUBLIC_BASE_URL": "http://labca.example.test"}, _ring(), "PUBLIC_BASE_URL"),
        ({"DATABASE_URL": "postgresql://u@h/db"}, _ring(), "DATABASE_URL"),
        ({"DATABASE_URL": "sqlite:///:memory:"}, _ring(), "DATABASE_URL"),
        ({"DATABASE_URL": "sqlite:///./labca.db"}, _ring(), "DATABASE_URL"),
        ({"DATABASE_URL": "sqlite:////tmp/labca.db"}, _ring(), "DATABASE_URL"),
        ({"DATABASE_URL": "sqlite:////data/../etc/x.db"}, _ring(), "DATABASE_URL"),
        ({"WORKLOAD_ISSUANCE_ENABLED": True, "WORKLOAD_ISSUER_CA_NAME": "I"}, _ring(), "WORKLOAD_TRUST_DOMAIN"),
        (
            {"WORKLOAD_ISSUANCE_ENABLED": True, "WORKLOAD_TRUST_DOMAIN": "t.example"},
            _ring(),
            "WORKLOAD_ISSUER_CA_NAME",
        ),
    ],
)
def test_each_rule_fails_individually(overrides, ring, expected):
    with pytest.raises(StartupCheckError) as info:
        run_startup_checks(_prod(**overrides), ring)
    assert expected in str(info.value)


def test_database_paths_below_data_pass():
    run_startup_checks(_prod(DATABASE_URL="sqlite:////data/sub/labca.db"), _ring())
    run_startup_checks(_prod(DATABASE_URL="sqlite:////data/./labca.db"), _ring())


def test_all_violations_are_listed_one_per_line():
    settings = _prod(
        SECRET_KEY="CHANGE_ME",
        ENABLE_API_DOCS=True,
        ADMIN_AUTH_MODE="none",
        PUBLIC_BASE_URL=None,
        DATABASE_URL="sqlite:///:memory:",
        WORKLOAD_ISSUANCE_ENABLED=True,
    )
    with pytest.raises(StartupCheckError) as info:
        run_startup_checks(settings, KeyRing({}))
    lines = str(info.value).splitlines()
    assert lines[0].startswith("Refusing to start with ENV=prod: ")
    body = "\n".join(lines[1:])
    for name in (
        "no KEK is loaded",
        "LABCA_ACTIVE_KEK_ID",
        "SECRET_KEY",
        "ENABLE_API_DOCS",
        "ADMIN_AUTH_MODE=none",
        "PUBLIC_BASE_URL",
        "DATABASE_URL",
        "WORKLOAD_TRUST_DOMAIN",
        "WORKLOAD_ISSUER_CA_NAME",
    ):
        assert name in body
    assert len(lines) - 1 >= 9
    assert all(line.startswith("- ") for line in lines[1:])


def test_values_never_appear_in_the_message():
    settings = _prod(
        SECRET_KEY=DISTINCT_SECRET[:20],  # too short, distinctive
        PUBLIC_BASE_URL="http://distinctive-host.example.test",
        DATABASE_URL="sqlite:////etc/distinctive-db-name.db",
    )
    with pytest.raises(StartupCheckError) as info:
        run_startup_checks(settings, _ring())
    message = str(info.value)
    assert DISTINCT_SECRET[:20] not in message
    assert "distinctive-host" not in message
    assert "distinctive-db-name" not in message
    assert "SECRET_KEY" in message


def test_non_prod_only_warns(caplog):
    settings = Settings(
        _env_file=None,
        ENV="dev",
        LABCA_KEK_DIR="",
        LABCA_ACTIVE_KEK_ID="",
        SECRET_KEY="CHANGE_ME",
        ENABLE_API_DOCS=True,
    )
    with caplog.at_level(logging.WARNING, logger="labca"):
        run_startup_checks(settings, KeyRing({}))
    text = caplog.text
    assert "SECRET_KEY" in text
    assert "ENABLE_API_DOCS" in text
    assert "PUBLIC_BASE_URL" in text
    assert "CHANGE_ME" not in text
