"""Security headers added to every HTTP response (pure ASGI)."""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)

# FastAPI's interactive docs load their assets from cdn.jsdelivr.net (decision D-017).
DOCS_CSP = (
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
    "font-src 'self' https://fonts.gstatic.com; worker-src 'self' blob:; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)

_DOCS_PATHS = frozenset({"/docs", "/redoc"})


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                wanted = {
                    "content-security-policy": DOCS_CSP if path in _DOCS_PATHS else CSP,
                    "x-content-type-options": "nosniff",
                    "x-frame-options": "DENY",
                    "referrer-policy": "no-referrer",
                    "cross-origin-opener-policy": "same-origin",
                }
                if (get_settings().PUBLIC_BASE_URL or "").startswith("https://"):
                    wanted["strict-transport-security"] = "max-age=31536000"
                for name, value in wanted.items():
                    if name not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)
