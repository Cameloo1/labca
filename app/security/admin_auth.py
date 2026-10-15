"""Admin authentication middleware (pure ASGI)."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import Settings, get_settings
from app.logging_config import logger
from app.security import access_jwt
from app.security.route_class import RouteClass, classify_scope

_FORWARDING_HEADERS = (b"x-forwarded-for", b"forwarded", b"x-real-ip")
_JWT_HEADER = b"cf-access-jwt-assertion"


def admin_email_set(settings: Settings) -> frozenset[str]:
    return frozenset(item.strip().lower() for item in settings.ADMIN_EMAILS.split(",") if item.strip())


def is_local_request(scope: Scope) -> bool:
    client = scope.get("client")
    if not client:
        return False
    try:
        address: Any = ipaddress.ip_address(client[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if not address.is_loopback:
        return False
    names = {name for name, _ in scope.get("headers", [])}
    return not any(header in names for header in _FORWARDING_HEADERS)


def _header(scope: Scope, name: bytes) -> Optional[str]:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


async def _deny(scope: Scope, receive: Receive, send: Send, mode: str, reason: str) -> None:
    logger.warning("Admin request denied", extra={"path": scope.get("path", ""), "mode": mode, "reason": reason})
    body = b"Forbidden\n"
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _decide(scope: Scope, settings: Settings) -> tuple[Optional[str], str]:
    """Return (principal, reason). principal is None when the request is denied."""
    mode = settings.ADMIN_AUTH_MODE
    if mode == "none":
        return "anonymous", "ok"
    if mode == "localhost_only":
        if is_local_request(scope):
            return "localhost", "ok"
        return None, "not_local"
    token = _header(scope, _JWT_HEADER)
    if token is not None:
        try:
            claims = access_jwt.validate_access_jwt(
                token,
                cache=access_jwt.get_jwks_cache(),
                audience=settings.CF_ACCESS_AUD or "",
                team_domain=settings.CF_ACCESS_TEAM_DOMAIN or "",
            )
            email = claims.get("email")
            if not isinstance(email, str):
                raise access_jwt.AccessJwtError("email_not_allowed")
            email = email.lower()
            if email not in admin_email_set(settings):
                raise access_jwt.AccessJwtError("email_not_allowed")
            return email, "ok"
        except access_jwt.AccessJwtError as exc:
            reason = exc.reason
    else:
        reason = "missing"
    if settings.ADMIN_BREAK_GLASS_LOCALHOST and is_local_request(scope):
        return "localhost", "ok"
    return None, reason


class AdminAuthMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or classify_scope(scope) is not RouteClass.ADMIN:
            await self.app(scope, receive, send)
            return
        settings = get_settings()
        principal, reason = _decide(scope, settings)
        if principal is None:
            await _deny(scope, receive, send, settings.ADMIN_AUTH_MODE, reason)
            return
        scope.setdefault("state", {})["admin_principal"] = principal
        await self.app(scope, receive, send)
