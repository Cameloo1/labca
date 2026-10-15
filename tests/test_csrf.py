"""Tests for the CSRF cookie middleware, token binding, and the csrf_protect dependency."""

from __future__ import annotations

import re
import time

import pytest
from itsdangerous import URLSafeTimedSerializer

from app.config import get_settings
from app.security.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    CSRF_HEADER,
    CSRF_MAX_AGE_SECONDS,
    make_token,
    new_cookie_value,
    token_matches,
)
from app.services.api_token_service import create_token


def _form_token(html: str) -> str:
    match = re.search(r'<input type="hidden" name="csrf_token" value="([^"]+)">', html)
    assert match, "hidden csrf_token input not found"
    return match.group(1)


def test_real_flow_cookie_and_hidden_input(client):
    page = client.get("/quick-cert")
    assert page.status_code == 200
    set_cookie = page.headers["set-cookie"]
    assert set_cookie.startswith(f"{CSRF_COOKIE_NAME}=")
    assert "HttpOnly" in set_cookie
    assert "SameSite=Lax" in set_cookie
    assert "Path=/" in set_cookie
    assert "Secure" not in set_cookie
    token = _form_token(page.text)
    cookie_value = client.cookies.get(CSRF_COOKIE_NAME)
    assert cookie_value and re.fullmatch(r"[A-Za-z0-9_-]{43}", cookie_value)
    assert token_matches(token, cookie_value)

    # A valid cookie is not replaced on the next request.
    again = client.get("/quick-cert")
    assert "set-cookie" not in again.headers

    response = client.post("/setup/step1", data={CSRF_FORM_FIELD: token}, follow_redirects=False)
    assert response.status_code == 303


def test_real_flow_post_to_quick_cert_is_not_blocked(client):
    token = _form_token(client.get("/quick-cert").text)
    response = client.post("/quick-cert", data={CSRF_FORM_FIELD: token, "mode": "simple"})
    assert response.status_code != 403


def test_post_without_token_is_forbidden(client):
    client.get("/quick-cert")
    response = client.post("/setup/step1", follow_redirects=False)
    assert response.status_code == 403
    assert "CSRF token missing or invalid." in response.text


def test_post_without_cookie_is_forbidden(client):
    value = new_cookie_value()
    response = client.post("/setup/step1", data={CSRF_FORM_FIELD: make_token(value)}, follow_redirects=False)
    # The middleware issues a fresh cookie, which cannot match a token made for another one.
    assert response.status_code == 403


def test_token_for_another_cookie_is_forbidden(client):
    client.cookies.set(CSRF_COOKIE_NAME, new_cookie_value())
    other = make_token(new_cookie_value())
    response = client.post("/setup/step1", data={CSRF_FORM_FIELD: other}, follow_redirects=False)
    assert response.status_code == 403


def test_tampered_token_is_forbidden(client, csrf):
    fields = csrf(client)
    token = fields[CSRF_FORM_FIELD]
    flipped = token[:-1] + ("A" if token[-1] != "A" else "B")
    for bad in (flipped, token + "x", "garbage", token.split(".")[0]):
        response = client.post("/setup/step1", data={CSRF_FORM_FIELD: bad}, follow_redirects=False)
        assert response.status_code == 403


def test_expired_token_is_forbidden(client, monkeypatch):

    value = new_cookie_value()
    client.cookies.set(CSRF_COOKIE_NAME, value)
    real_now = time.time()
    with monkeypatch.context() as patched:
        patched.setattr(time, "time", lambda: real_now - CSRF_MAX_AGE_SECONDS - 10)
        old = make_token(value)
    assert not token_matches(old, value)
    response = client.post("/setup/step1", data={CSRF_FORM_FIELD: old}, follow_redirects=False)
    assert response.status_code == 403


def test_token_signed_with_other_secret_is_forbidden(client):
    value = new_cookie_value()
    client.cookies.set(CSRF_COOKIE_NAME, value)
    forged = URLSafeTimedSerializer("another-secret", salt="labca-csrf-v1").dumps(value)
    response = client.post("/setup/step1", data={CSRF_FORM_FIELD: forged}, follow_redirects=False)
    assert response.status_code == 403


def test_header_token_is_accepted(client, csrf_headers):
    response = client.post("/setup/step1", headers=csrf_headers(client), follow_redirects=False)
    assert response.status_code == 303


def test_bad_header_token_is_forbidden(client, csrf):
    form = csrf(client)
    response = client.post("/setup/step1", data=form, headers={CSRF_HEADER: "garbage"}, follow_redirects=False)
    assert response.status_code == 403


def test_safe_methods_need_no_token(client):
    assert client.get("/help").status_code == 200
    assert client.head("/help").status_code in (200, 405)
    assert client.options("/help").status_code != 403


def test_malformed_cookie_is_replaced(client):
    client.cookies.set(CSRF_COOKIE_NAME, "short")
    response = client.get("/help")
    assert response.headers["set-cookie"].startswith(f"{CSRF_COOKIE_NAME}=")
    assert "short" not in response.headers["set-cookie"]


def test_machine_route_is_not_blocked_by_csrf(client, db_session):
    _, raw = create_token("csrf-machine", {"issue": True, "read": True}, None, db_session)
    response = client.post(
        "/api/v1/certificates", headers={"Authorization": f"Bearer {raw}"}, json={"common_name": "x"}
    )
    assert response.status_code != 403
    assert "set-cookie" not in response.headers


def test_public_route_gets_no_cookie(client):
    assert "set-cookie" not in client.get("/pki/index.json").headers
    assert "set-cookie" not in client.get("/health").headers


def test_secure_flag_only_with_https_base_url(client, monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://lab.example")
    get_settings.cache_clear()
    assert "Secure" not in client.get("/help").headers["set-cookie"]
    client.cookies.clear()
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://lab.example")
    get_settings.cache_clear()
    assert "Secure" in client.get("/help").headers["set-cookie"]


@pytest.mark.parametrize("cookie", ["", "x"])
def test_token_matches_rejects_empty_and_bad_input(cookie):
    assert not token_matches("", cookie)
    assert not token_matches("whatever", cookie)
    assert not token_matches(make_token("abc"), "")
