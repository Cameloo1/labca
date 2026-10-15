"""Security headers on every response class."""

from __future__ import annotations

import pytest

from app.config import get_settings

REQUIRED = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
}


def _assert_strict(response):
    for name, value in REQUIRED.items():
        assert response.headers[name] == value
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self';" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-eval" not in csp
    assert "unsafe-inline" not in csp
    assert "http:" not in csp and "https:" not in csp


def test_admin_page(client):
    _assert_strict(client.get("/help"))


def test_public_pki(client):
    response = client.get("/pki/index.json")
    _assert_strict(response)


def test_machine_401(client):
    response = client.post("/api/v1/certificates", json={})
    assert response.status_code == 401
    _assert_strict(response)


def test_404(client):
    response = client.get("/no-such-page")
    assert response.status_code == 404
    _assert_strict(response)


def test_admin_auth_403(client, monkeypatch):
    monkeypatch.setenv("ADMIN_AUTH_MODE", "localhost_only")
    get_settings.cache_clear()
    response = client.get("/help")
    assert response.status_code == 403
    _assert_strict(response)


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_docs_csp_exception(client, path):
    response = client.get(path)
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "https://cdn.jsdelivr.net" in csp
    assert "unsafe-eval" not in csp
    assert "http://" not in csp
    assert response.headers["x-frame-options"] == "DENY"


def test_hsts_only_with_https(client, monkeypatch):
    assert "strict-transport-security" not in client.get("/help").headers
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://lab.example")
    get_settings.cache_clear()
    assert "strict-transport-security" not in client.get("/help").headers
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://lab.example")
    get_settings.cache_clear()
    assert client.get("/help").headers["strict-transport-security"] == "max-age=31536000"
    assert client.get("/health").headers["strict-transport-security"] == "max-age=31536000"


def test_handler_set_header_is_kept():
    import asyncio

    from app.security.headers import SecurityHeadersMiddleware

    sent = []

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"x-frame-options", b"SAMEORIGIN")]})
        await send({"type": "http.response.body", "body": b""})

    async def collect(message):
        sent.append(message)

    asyncio.run(SecurityHeadersMiddleware(inner)({"type": "http", "path": "/x"}, None, collect))
    headers = [v for k, v in sent[0]["headers"] if k == b"x-frame-options"]
    assert headers == [b"SAMEORIGIN"]
