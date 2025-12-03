from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.logging_config import logger


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger.info(
            "Incoming request",
            extra={"path": request.url.path, "method": request.method},
        )
        response = await call_next(request)
        logger.info(
            "Outgoing response",
            extra={"path": request.url.path, "status_code": response.status_code},
        )
        return response
