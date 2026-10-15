"""Tests for Cloudflare Access JWT validation and the JWKS cache."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.security.access_jwt import AccessJwtError, JwksCache, fetch_access_jwks, validate_access_jwt

TEAM = "lab.cloudflareaccess.com"
AUD = "a" * 64


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk_for(private_key, kid: str) -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


def make_token(private_key, kid="k1", *, email="admin@example.com", aud=AUD, iss=f"https://{TEAM}", iat=None, exp=None):
    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": [aud],
        "iat": now if iat is None else iat,
        "exp": now + 300 if exp is None else exp,
        "email": email,
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid} if kid else {})


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Fetcher:
    """Returns the n-th document on the n-th call (the last one repeats); raises exceptions."""

    def __init__(self, *documents) -> None:
        self.documents = list(documents)
        self.calls = 0

    def __call__(self) -> dict:
        self.calls += 1
        document = self.documents[min(self.calls, len(self.documents)) - 1]
        if isinstance(document, Exception):
            raise document
        return document


@pytest.fixture(scope="module")
def key():
    return make_key()


@pytest.fixture
def cache(key):
    return JwksCache(Fetcher({"keys": [jwk_for(key, "k1")]}))


def validate(token, cache, **kwargs):
    return validate_access_jwt(token, cache=cache, audience=AUD, team_domain=TEAM, **kwargs)


def reason(token, cache, **kwargs) -> str:
    with pytest.raises(AccessJwtError) as info:
        validate(token, cache, **kwargs)
    return info.value.reason


def test_valid_token(key, cache):
    claims = validate(make_token(key), cache)
    assert claims["email"] == "admin@example.com"


def test_expired_beyond_leeway(key, cache):
    now = int(time.time())
    assert reason(make_token(key, iat=now - 600, exp=now - 120), cache) == "expired"


def test_expired_within_leeway_accepted(key, cache):
    now = int(time.time())
    assert validate(make_token(key, iat=now - 600, exp=now - 30), cache)["email"]


def test_fixed_clock(key, cache):
    token = make_token(key, iat=1000, exp=1300)
    assert validate(token, cache, now=1200.0)["email"]
    assert validate(token, cache, now=1350.0)["email"]
    assert reason(token, cache, now=1400.0) == "expired"
    assert reason(token, cache, now=800.0) == "malformed"


def test_wrong_audience(key, cache):
    assert reason(make_token(key, aud="b" * 64), cache) == "bad_audience"


def test_wrong_issuer(key, cache):
    assert reason(make_token(key, iss="https://evil.cloudflareaccess.com"), cache) == "bad_issuer"


def test_bad_signature(cache):
    assert reason(make_token(make_key(), kid="k1"), cache) == "bad_signature"


def test_hs256_signed_with_public_key_rejected(key, cache):
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = int(time.time())
    claims = {"iss": f"https://{TEAM}", "aud": [AUD], "iat": now, "exp": now + 300, "email": "admin@example.com"}
    header = {"alg": "HS256", "typ": "JWT", "kid": "k1"}
    signing = _b64(json.dumps(header).encode()) + b"." + _b64(json.dumps(claims).encode())
    signature = _b64(hmac.new(public_pem, signing, hashlib.sha256).digest())
    assert reason((signing + b"." + signature).decode(), cache) == "malformed"


def test_alg_none_rejected(cache):
    now = int(time.time())
    claims = {"iss": f"https://{TEAM}", "aud": [AUD], "iat": now, "exp": now + 300, "email": "admin@example.com"}
    header = {"alg": "none", "typ": "JWT", "kid": "k1"}
    token = (_b64(json.dumps(header).encode()) + b"." + _b64(json.dumps(claims).encode()) + b".").decode()
    assert reason(token, cache) == "malformed"


def test_missing_kid(key, cache):
    assert reason(make_token(key, kid=None), cache) == "malformed"


def test_missing_and_malformed_tokens(cache):
    assert reason("", cache) == "missing"
    assert reason("not-a-jwt", cache) == "malformed"
    assert reason("a.b", cache) == "malformed"
    assert reason("a.b.c.d", cache) == "malformed"
    assert reason("a.b.c", cache) == "malformed"


def test_oversized_token(cache):
    assert reason("a." + "b" * 9000 + ".c", cache) == "malformed"


def test_missing_required_claim(key, cache):
    now = int(time.time())
    token = jwt.encode(
        {"iss": f"https://{TEAM}", "aud": [AUD], "exp": now + 300}, key, algorithm="RS256", headers={"kid": "k1"}
    )
    assert reason(token, cache) == "malformed"


def test_unknown_kid_triggers_one_refetch_and_succeeds(key):
    clock = FakeClock()
    other = make_key()
    fetch = Fetcher({"keys": [jwk_for(key, "k1")]}, {"keys": [jwk_for(key, "k1"), jwk_for(other, "k2")]})
    cache = JwksCache(fetch, clock=clock)
    assert validate(make_token(key), cache)["email"]
    assert fetch.calls == 1
    clock.now += 31
    assert validate(make_token(other, kid="k2"), cache)["email"]
    assert fetch.calls == 2


def test_unknown_kid_twice_within_window_fetches_once(key):
    clock = FakeClock()
    fetch = Fetcher({"keys": [jwk_for(key, "k1")]})
    cache = JwksCache(fetch, clock=clock)
    token = make_token(key, kid="ghost")
    assert reason(token, cache) == "unknown_kid"
    assert fetch.calls == 1
    clock.now += 10
    assert reason(token, cache) == "unknown_kid"
    assert fetch.calls == 1
    clock.now += 25
    assert reason(token, cache) == "unknown_kid"
    assert fetch.calls == 2


def test_ttl_expiry_refetches(key):
    clock = FakeClock()
    fetch = Fetcher({"keys": [jwk_for(key, "k1")]})
    cache = JwksCache(fetch, ttl_seconds=600, clock=clock)
    token = make_token(key)
    validate(token, cache)
    clock.now += 500
    validate(token, cache)
    assert fetch.calls == 1
    clock.now += 101
    validate(token, cache)
    assert fetch.calls == 2


def test_fetch_failure_with_empty_cache_is_jwks_unavailable(key):
    cache = JwksCache(Fetcher(RuntimeError("boom")))
    assert reason(make_token(key), cache) == "jwks_unavailable"


def test_fetch_failure_after_ttl_is_jwks_unavailable(key):
    clock = FakeClock()
    cache = JwksCache(Fetcher({"keys": [jwk_for(key, "k1")]}, RuntimeError("boom")), ttl_seconds=600, clock=clock)
    validate(make_token(key), cache)
    clock.now += 700
    assert reason(make_token(key), cache) == "jwks_unavailable"


def test_failed_refetch_while_fresh_is_unknown_kid(key):
    clock = FakeClock()
    cache = JwksCache(Fetcher({"keys": [jwk_for(key, "k1")]}, RuntimeError("boom")), clock=clock)
    validate(make_token(key), cache)
    clock.now += 40
    assert reason(make_token(key, kid="ghost"), cache) == "unknown_kid"
    # The known key still works from the fresh cache.
    assert validate(make_token(key), cache)["email"]


def test_non_rsa_and_broken_keys_ignored(key):
    document = {
        "keys": [
            {"kty": "EC", "kid": "ec1", "crv": "P-256", "x": "AA", "y": "AA"},
            {"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"},
            {"kty": "RSA", "n": "AA", "e": "AQAB"},
            "junk",
            jwk_for(key, "k1"),
        ]
    }
    cache = JwksCache(Fetcher(document))
    assert validate(make_token(key), cache)["email"]
    assert reason(make_token(key, kid="ec1"), cache) == "unknown_kid"


def test_bad_jwks_shape_fails_closed(key):
    cache = JwksCache(Fetcher({"nokeys": []}))
    assert reason(make_token(key), cache) == "jwks_unavailable"


def _route_httpx_get_through(handler, monkeypatch):
    transport = httpx.MockTransport(handler)

    def fake_get(url, **kwargs):
        with httpx.Client(transport=transport) as client:
            return client.get(url, timeout=kwargs["timeout"], follow_redirects=kwargs["follow_redirects"])

    monkeypatch.setattr(httpx, "get", fake_get)


def test_fetch_access_jwks_ok(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"keys": [{"kid": "k1"}]})

    _route_httpx_get_through(handler, monkeypatch)
    assert fetch_access_jwks(TEAM) == {"keys": [{"kid": "k1"}]}
    assert seen["url"] == f"https://{TEAM}/cdn-cgi/access/certs"


def test_fetch_access_jwks_uses_timeout_and_no_redirects(monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return httpx.Response(200, json={"keys": []})

    monkeypatch.setattr(httpx, "get", fake_get)
    fetch_access_jwks(TEAM)
    assert captured["timeout"] == 5.0
    assert captured["follow_redirects"] is False


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(302, headers={"location": "https://evil.example/"}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json=[1, 2]),
        httpx.Response(200, json={"keys": "x"}),
    ],
)
def test_fetch_access_jwks_errors(monkeypatch, response):
    _route_httpx_get_through(lambda request: response, monkeypatch)
    with pytest.raises(ValueError):
        fetch_access_jwks(TEAM)
