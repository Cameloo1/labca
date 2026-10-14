from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from app.logging_config import logger

templates = Jinja2Templates(directory="app/templates")


async def http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api"):
        payload = {
            "detail": exc.detail,
            "status": exc.status_code,
            "error_code": f"HTTP_{exc.status_code}",
        }
        return JSONResponse(payload, status_code=exc.status_code)
    if exc.status_code == 404:
        return templates.TemplateResponse(request, "error_404.html", {"request": request}, status_code=404)
    return templates.TemplateResponse(
        request,
        "error_generic.html",
        {"request": request, "status_code": exc.status_code, "detail": exc.detail},
        status_code=exc.status_code,
    )


async def server_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled application error")
    if request.url.path.startswith("/api"):
        payload = {"detail": "Internal server error", "status": 500, "error_code": "SERVER_ERROR"}
        return JSONResponse(payload, status_code=500)
    return templates.TemplateResponse(request, "error_500.html", {"request": request}, status_code=500)
