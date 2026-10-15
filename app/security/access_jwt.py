"""Cloudflare Access JWT validation with a small JWKS cache."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

import httpx
import jwt

from app.config import get_settings

MAX_TOKEN_BYTES = 8192
LEEWAY_SECONDS = 60


class AccessJwtError(Exception):
    """Token rejected. ``reason`` is a short code, never token content."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class JwksCache:
    def __init__(
        self,
        fetch: Callable[[], dict],
        ttl_seconds: int = 600,
        min_refetch_seconds: int = 30,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._ttl = ttl_seconds
        self._min_refetch = min_refetch_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: Optional[float] = None

    def _refresh(self) -> None:
        document = self._fetch()
        keys: dict[str, Any] = {}
        entries = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise ValueError("JWKS document has no keys list.")
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("kty") != "RSA" or not isinstance(entry.get("kid"), str):
                continue
            try:
                keys[entry["kid"]] = jwt.PyJWK(entry, algorithm="RS256").key
            except Exception:  # one unusable key must not hide the others
                continue
        self._keys = keys
        self._fetched_at = self._clock()

    def _age(self) -> Optional[float]:
        if self._fetched_at is None:
            return None
        return self._clock() - self._fetched_at

    def get_key(self, kid: str) -> Any:
        with self._lock:
            age = self._age()
            expired = age is None or age > self._ttl or not self._keys
            if expired:
                try:
                    self._refresh()
                except Exception:  # any fetch or parse failure fails closed
                    raise AccessJwtError("jwks_unavailable") from None
            if kid in self._keys:
                return self._keys[kid]
            age = self._age()
            if not expired and age is not None and age > self._min_refetch:
                try:
                    self._refresh()
                except Exception:  # cache is still fresh; treat as unknown kid
                    raise AccessJwtError("unknown_kid") from None
                if kid in self._keys:
                    return self._keys[kid]
            raise AccessJwtError("unknown_kid")


def fetch_access_jwks(team_domain: str) -> dict:
    url = f"https://{team_domain}/cdn-cgi/access/certs"
    response = httpx.get(url, timeout=5.0, follow_redirects=False)
    if response.status_code != 200:
        raise ValueError(f"JWKS endpoint returned status {response.status_code}.")
    document = response.json()
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("JWKS document must be an object with a keys list.")
    return document


def validate_access_jwt(
    token: str,
    *,
    cache: JwksCache,
    audience: str,
    team_domain: str,
    now: Optional[float] = None,
) -> dict:
    """Validate the token and return its claims; raise AccessJwtError otherwise."""
    if not token:
        raise AccessJwtError("missing")
    if len(token.encode("utf-8", "replace")) > MAX_TOKEN_BYTES or token.count(".") != 2:
        raise AccessJwtError("malformed")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise AccessJwtError("malformed") from None
    kid = header.get("kid")
    if header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
        raise AccessJwtError("malformed")
    key = cache.get_key(kid)
    # PyJWT reads the current time itself; ``now`` is accepted so callers can pin it in tests.
    try:
        if now is None:
            return jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=audience,
                issuer=f"https://{team_domain}",
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        return _decode_at(token, key, audience, team_domain, now)
    except jwt.ExpiredSignatureError:
        raise AccessJwtError("expired") from None
    except jwt.InvalidAudienceError:
        raise AccessJwtError("bad_audience") from None
    except jwt.InvalidIssuerError:
        raise AccessJwtError("bad_issuer") from None
    except jwt.InvalidSignatureError:
        raise AccessJwtError("bad_signature") from None
    except jwt.PyJWTError:
        raise AccessJwtError("malformed") from None


def _decode_at(token: str, key: Any, audience: str, team_domain: str, now: float) -> dict:
    """Decode with a fixed clock by checking exp/iat ourselves after the signature check."""
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=audience,
        issuer=f"https://{team_domain}",
        options={"require": ["exp", "iat", "iss", "aud"], "verify_exp": False, "verify_iat": False},
    )
    exp = claims.get("exp")
    iat = claims.get("iat")
    if not isinstance(exp, (int, float)) or not isinstance(iat, (int, float)):
        raise jwt.InvalidTokenError("bad time claims")
    if exp + LEEWAY_SECONDS <= now:
        raise jwt.ExpiredSignatureError("expired")
    if iat - LEEWAY_SECONDS > now:
        raise jwt.ImmatureSignatureError("iat in the future")
    return claims


_cache: Optional[JwksCache] = None
_cache_lock = threading.Lock()


def get_jwks_cache() -> JwksCache:
    global _cache
    with _cache_lock:
        if _cache is None:
            team_domain = get_settings().CF_ACCESS_TEAM_DOMAIN or ""
            _cache = JwksCache(lambda: fetch_access_jwks(team_domain))
        return _cache


def set_jwks_cache(cache: Optional[JwksCache]) -> None:
    global _cache
    with _cache_lock:
        _cache = cache
