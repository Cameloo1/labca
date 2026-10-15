"""Tests for admin authentication by route class and mode."""

from __future__ import annotations

import asyncio
import logging
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.main import app
from app.security.access_jwt import JwksCache, set_jwks_cache
from app.security.admin_auth import AdminAuthMiddleware, admin_email_set, is_local_request
from app.services.keystore import KeyRing
from app.startup import StartupCheckError, run_startup_checks
from tests.test_access_jwt import AUD, TEAM, jwk_for, make_key, make_token

ADMIN_PATH = "/cas"
PUBLIC_PATH = "/pki/index.json"
MACHINE_PATH = "/api/v1/certificates"
OUTSIDE = ("10.0.0.5", 4000)
LOOPBACK = ("127.0.0.1", 4000)


def _mode(monkeypatch, mode: str, **extra: str) -> None:
    monkeypatch.setenv("ADMIN_AUTH_MODE", mode)
    for name, value in extra.items():
        monkeypatch.setenv(name, value)
    get_settings.cache_clear()


def call(path: str, *, client=LOOPBACK, headers=(), raw_path=None, scope_type="http"):
    """Run the middleware around a tiny inner app. Returns (status or None, response headers, body, scope)."""
    seen = {}

    async def inner(scope, receive, send):
        seen["reached"] = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    sent = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": scope_type,
        "path": path,
        "raw_path": raw_path if raw_path is not None else path.encode(),
        "client": client,
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers],
    }
    asyncio.run(AdminAuthMiddleware(inner)(scope, None, send))
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return (
        start["status"] if start else None,
        dict(start["headers"]) if start else {},
        body,
        scope,
        seen.get("reached", False),
    )


def test_mode_none_allows_everything(monkeypatch):
    _mode(monkeypatch, "none")
    for path in (ADMIN_PATH, PUBLIC_PATH, MACHINE_PATH):
        status, _, _, _, reached = call(path, client=OUTSIDE)
        assert status == 204 and reached


def test_default_mode_is_none():
    assert Settings(_env_file=None).ADMIN_AUTH_MODE == "none"


@pytest.mark.parametrize("client", [("127.0.0.1", 1), ("127.8.9.10", 1), ("::1", 1), ("::ffff:127.0.0.1", 1)])
def test_localhost_only_allows_loopback(monkeypatch, client):
    _mode(monkeypatch, "localhost_only")
    status, _, _, scope, reached = call(ADMIN_PATH, client=client)
    assert status == 204 and reached
    assert scope["state"]["admin_principal"] == "localhost"


@pytest.mark.parametrize("client", [OUTSIDE, ("::ffff:10.0.0.5", 1), ("testclient", 1), ("", 1), None])
def test_localhost_only_denies_others(monkeypatch, client):
    _mode(monkeypatch, "localhost_only")
    status, headers, body, _, reached = call(ADMIN_PATH, client=client)
    assert status == 403 and not reached
    assert body == b"Forbidden\n"
    assert headers[b"content-type"] == b"text/plain; charset=utf-8"
    assert headers[b"cache-control"] == b"no-store"


@pytest.mark.parametrize("header", ["X-Forwarded-For", "Forwarded", "X-Real-IP"])
def test_localhost_only_denies_forwarded_loopback(monkeypatch, header):
    _mode(monkeypatch, "localhost_only")
    status, _, _, _, reached = call(ADMIN_PATH, client=LOOPBACK, headers=[(header, "127.0.0.1")])
    assert status == 403 and not reached


def test_localhost_only_leaves_public_and_machine_alone(monkeypatch):
    _mode(monkeypatch, "localhost_only")
    for path in (PUBLIC_PATH, MACHINE_PATH, "/health", "/static/app.css"):
        status, _, _, _, reached = call(path, client=OUTSIDE)
        assert status == 204 and reached


def test_prefix_trick_is_treated_as_admin(monkeypatch):
    _mode(monkeypatch, "localhost_only")
    status, _, _, _, reached = call("/pki/../cas", client=OUTSIDE)
    assert status == 403 and not reached
    status, _, _, _, reached = call("/pki/index.json", client=OUTSIDE, raw_path=b"/pki/%2e%2e/cas")
    assert status == 403 and not reached


def test_non_http_scopes_pass_through(monkeypatch):
    _mode(monkeypatch, "localhost_only")
    status, _, _, _, reached = call(ADMIN_PATH, client=OUTSIDE, scope_type="websocket")
    assert reached and status == 204


def test_denial_is_logged_without_headers(monkeypatch, caplog):
    _mode(monkeypatch, "localhost_only")
    with caplog.at_level(logging.WARNING, logger="labca"):
        call(ADMIN_PATH, client=OUTSIDE, headers=[("Authorization", "Bearer secret-value")])
    records = [r for r in caplog.records if r.getMessage() == "Admin request denied"]
    assert len(records) == 1
    assert records[0].path == ADMIN_PATH
    assert records[0].mode == "localhost_only"
    assert records[0].reason == "not_local"
    assert "secret-value" not in caplog.text


def test_is_local_request_missing_client():
    assert not is_local_request({"headers": []})


def test_admin_email_set_normalizes():
    settings = Settings(_env_file=None, ADMIN_EMAILS=" Admin@Example.com, ,b@example.com ,")
    assert admin_email_set(settings) == frozenset({"admin@example.com", "b@example.com"})
    assert admin_email_set(Settings(_env_file=None)) == frozenset()


# --- cloudflare_access ----------------------------------------------------------------------


@pytest.fixture
def cf(monkeypatch):
    key = make_key()
    set_jwks_cache(JwksCache(lambda: {"keys": [jwk_for(key, "k1")]}))
    _mode(
        monkeypatch,
        "cloudflare_access",
        CF_ACCESS_TEAM_DOMAIN=TEAM,
        CF_ACCESS_AUD=AUD,
        ADMIN_EMAILS="Admin@Example.com, ops@example.com",
    )
    return key


def _jwt_header(token: str):
    return [("Cf-Access-Jwt-Assertion", token)]


def test_cf_valid_token_allowed_and_principal_set(cf):
    status, _, _, scope, reached = call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(make_token(cf)))
    assert status == 204 and reached
    assert scope["state"]["admin_principal"] == "admin@example.com"


def test_cf_email_claim_is_case_insensitive(cf):
    token = make_token(cf, email="OPS@Example.COM")
    status, _, _, scope, _ = call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(token))
    assert status == 204
    assert scope["state"]["admin_principal"] == "ops@example.com"


def test_cf_no_header_denied(cf):
    status, _, body, _, reached = call(ADMIN_PATH, client=OUTSIDE)
    assert status == 403 and not reached and body == b"Forbidden\n"


def test_cf_email_not_allowed_denied(cf):
    token = make_token(cf, email="stranger@example.com")
    status, _, _, _, reached = call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(token))
    assert status == 403 and not reached


def test_cf_token_without_email_denied(cf):
    import jwt

    now = int(time.time())
    token = jwt.encode(
        {"iss": f"https://{TEAM}", "aud": [AUD], "iat": now, "exp": now + 300},
        cf,
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    status, _, _, _, _ = call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(token))
    assert status == 403


@pytest.mark.parametrize("bad", ["garbage", "a.b.c"])
def test_cf_bad_token_denied(cf, bad):
    status, _, _, _, _ = call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(bad))
    assert status == 403


def test_cf_wrong_audience_and_expired_denied(cf):
    now = int(time.time())
    assert call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(make_token(cf, aud="z" * 40)))[0] == 403
    expired = make_token(cf, iat=now - 900, exp=now - 600)
    assert call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(expired))[0] == 403


def test_cf_jwks_unavailable_fails_closed(cf):
    def broken():
        raise RuntimeError("no network")

    set_jwks_cache(JwksCache(broken))
    assert call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(make_token(cf)))[0] == 403


def test_cf_break_glass_off_denies_localhost(cf):
    assert call(ADMIN_PATH, client=LOOPBACK)[0] == 403


def test_cf_break_glass_on_allows_localhost(cf, monkeypatch):
    monkeypatch.setenv("ADMIN_BREAK_GLASS_LOCALHOST", "true")
    get_settings.cache_clear()
    status, _, _, scope, reached = call(ADMIN_PATH, client=LOOPBACK)
    assert status == 204 and reached
    assert scope["state"]["admin_principal"] == "localhost"


def test_cf_break_glass_on_denies_forwarded_localhost(cf, monkeypatch):
    monkeypatch.setenv("ADMIN_BREAK_GLASS_LOCALHOST", "true")
    get_settings.cache_clear()
    status, _, _, _, reached = call(ADMIN_PATH, client=LOOPBACK, headers=[("X-Forwarded-For", "127.0.0.1")])
    assert status == 403 and not reached


def test_cf_break_glass_on_denies_remote(cf, monkeypatch):
    monkeypatch.setenv("ADMIN_BREAK_GLASS_LOCALHOST", "true")
    get_settings.cache_clear()
    assert call(ADMIN_PATH, client=OUTSIDE)[0] == 403


def test_cf_public_route_needs_no_token(cf, client):
    with TestClient(app, client=("1.2.3.4", 5000)) as remote:
        assert remote.get(PUBLIC_PATH).status_code == 200
        assert remote.get("/health").status_code == 200
        assert remote.get("/help").status_code == 403
        assert remote.post(MACHINE_PATH, json={}).status_code == 401


def test_cf_through_full_app_with_token(cf, client):
    with TestClient(app, client=("1.2.3.4", 5000)) as remote:
        ok = remote.get("/help", headers={"Cf-Access-Jwt-Assertion": make_token(cf)})
        assert ok.status_code == 200


def test_no_log_record_contains_the_jwt(cf, caplog):
    token = make_token(cf, email="stranger@example.com")
    good = make_token(cf)
    with caplog.at_level(logging.DEBUG):
        call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(token))
        call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header("garbage.jwt.value"))
        call(ADMIN_PATH, client=OUTSIDE, headers=_jwt_header(good))
    # The two rejected calls were logged, so the checks below inspect real records.
    assert sum(record.getMessage() == "Admin request denied" for record in caplog.records) == 2
    for record in caplog.records:
        blob = record.getMessage() + " ".join(str(v) for v in record.__dict__.values())
        assert token not in blob and good not in blob and "garbage.jwt.value" not in blob
    assert token not in caplog.text and good not in caplog.text


# --- startup checks and settings -------------------------------------------------------------


def _startup(**values) -> None:
    defaults = {"ENV": "dev", "LABCA_KEK_DIR": "", "LABCA_ACTIVE_KEK_ID": ""}
    run_startup_checks(Settings(_env_file=None, **{**defaults, **values}), KeyRing({}))


def test_startup_prod_refuses_mode_none():
    with pytest.raises(StartupCheckError, match="ADMIN_AUTH_MODE=none is not allowed in prod."):
        run_startup_checks(
            Settings(_env_file=None, ENV="prod", ADMIN_AUTH_MODE="none"),
            KeyRing({"k": bytes(32)}, active_kek_id="k"),
        )


def test_startup_dev_allows_mode_none():
    _startup(ADMIN_AUTH_MODE="none")


def test_startup_prod_accepts_localhost_only():
    run_startup_checks(
        Settings(_env_file=None, ENV="prod", ADMIN_AUTH_MODE="localhost_only"),
        KeyRing({"k": bytes(32)}, active_kek_id="k"),
    )


COMPLETE = {"CF_ACCESS_TEAM_DOMAIN": TEAM, "CF_ACCESS_AUD": AUD, "ADMIN_EMAILS": "a@example.com"}


def test_startup_cloudflare_access_complete_is_accepted():
    _startup(ADMIN_AUTH_MODE="cloudflare_access", **COMPLETE)


@pytest.mark.parametrize("missing", ["CF_ACCESS_TEAM_DOMAIN", "CF_ACCESS_AUD", "ADMIN_EMAILS"])
def test_startup_cloudflare_access_names_missing_setting(missing):
    values = {k: v for k, v in COMPLETE.items() if k != missing}
    with pytest.raises(StartupCheckError) as info:
        _startup(ADMIN_AUTH_MODE="cloudflare_access", **values)
    assert missing in str(info.value)
    for other in COMPLETE:
        if other != missing:
            assert other not in str(info.value)


def test_startup_cloudflare_access_blank_emails_is_missing():
    with pytest.raises(StartupCheckError, match="ADMIN_EMAILS"):
        _startup(ADMIN_AUTH_MODE="cloudflare_access", **{**COMPLETE, "ADMIN_EMAILS": " , "})


def test_team_domain_validator():
    assert Settings(_env_file=None, CF_ACCESS_TEAM_DOMAIN="").CF_ACCESS_TEAM_DOMAIN is None
    assert Settings(_env_file=None, CF_ACCESS_TEAM_DOMAIN="Lab.CloudflareAccess.com").CF_ACCESS_TEAM_DOMAIN == TEAM
    for bad in (
        "example.com",
        "lab.cloudflareaccess.com.evil.com",
        "-.x/cloudflareaccess.com",
        "a.b.cloudflareaccess.com",
    ):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, CF_ACCESS_TEAM_DOMAIN=bad)


def test_aud_validator():
    assert Settings(_env_file=None, CF_ACCESS_AUD="").CF_ACCESS_AUD is None
    assert Settings(_env_file=None, CF_ACCESS_AUD="abc123").CF_ACCESS_AUD == "abc123"
    for bad in ("has space", "dash-ed", "a" * 129):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, CF_ACCESS_AUD=bad)


def test_auth_mode_rejects_unknown_value():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, ADMIN_AUTH_MODE="open")
