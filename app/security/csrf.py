"""CSRF protection: signed token bound to a double-submit cookie."""

from __future__ import annotations

import hmac
import re
import secrets

from fastapi import HTTPException, Request
from itsdangerous import URLSafeTimedSerializer
from markupsafe import Markup, escape
from starlette.datastructures import MutableHeaders
from starlette.requests import Request as StarletteRequest
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings
from app.logging_config import logger
from app.security.route_class import RouteClass, classify_scope

CSRF_COOKIE_NAME = "labca_csrf"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"
CSRF_MAX_AGE_SECONDS = 8 * 3600

_COOKIE_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def new_cookie_value() -> str:
    return secrets.token_urlsafe(32)


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().SECRET_KEY, salt="labca-csrf-v1")


def make_token(cookie_value: str) -> str:
    return _serializer().dumps(cookie_value)


def token_matches(token: str, cookie_value: str) -> bool:
    if not token or not cookie_value:
        return False
    try:
        bound = _serializer().loads(token, max_age=CSRF_MAX_AGE_SECONDS)
    except Exception:  # any signature, age, or decoding error means no match
        return False
    if not isinstance(bound, str):
        return False
    return hmac.compare_digest(bound.encode(), cookie_value.encode())


class CsrfCookieMiddleware:
    """Issue the CSRF cookie on ADMIN requests that do not carry a valid-looking one."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or classify_scope(scope) is not RouteClass.ADMIN:
            await self.app(scope, receive, send)
            return
        existing = StarletteRequest(scope).cookies.get(CSRF_COOKIE_NAME)
        state = scope.setdefault("state", {})
        if existing is not None and _COOKIE_RE.fullmatch(existing):
            state["csrf_cookie"] = existing
            await self.app(scope, receive, send)
            return
        value = new_cookie_value()
        state["csrf_cookie"] = value
        cookie = f"{CSRF_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax"
        public_base = get_settings().PUBLIC_BASE_URL or ""
        if public_base.startswith("https://"):
            cookie += "; Secure"

        async def send_with_cookie(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.append("set-cookie", cookie)
            await send(message)

        await self.app(scope, receive, send_with_cookie)


def csrf_input(request: Request) -> Markup:
    cookie_value = getattr(request.state, "csrf_cookie", "")
    token = make_token(cookie_value)
    return Markup('<input type="hidden" name="{}" value="{}">').format(CSRF_FORM_FIELD, escape(token))


async def csrf_protect(request: Request) -> None:
    if request.method in _SAFE_METHODS:
        return
    token = request.headers.get(CSRF_HEADER)
    if not token:
        form = await request.form()
        field = form.get(CSRF_FORM_FIELD)
        token = field if isinstance(field, str) else None
    cookie_value = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not token or not token_matches(token, cookie_value):
        logger.warning("CSRF check failed", extra={"path": request.url.path, "method": request.method})
        raise HTTPException(403, "CSRF token missing or invalid.")
