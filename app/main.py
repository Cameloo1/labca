from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import get_settings
from .error_handlers import http_exception_handler, server_exception_handler
from .logging_config import install_redaction_filter
from .middleware import RequestLoggingMiddleware
from .routes import api as api_routes
from .routes import api_ui as api_ui_routes
from .routes import audit as audit_routes
from .routes import cas as cas_routes
from .routes import certificates as certificates_routes
from .routes import help as help_routes
from .routes import home as home_routes
from .routes import notifications as notifications_routes
from .routes import pki as pki_routes
from .routes import profiles as profiles_routes
from .routes import quick_cert as quick_cert_routes
from .routes import settings as settings_routes
from .routes import setup as setup_routes
from .routes import workload as workload_routes
from .security.admin_auth import AdminAuthMiddleware
from .security.csrf import CsrfCookieMiddleware, csrf_protect
from .security.headers import SecurityHeadersMiddleware
from .startup import run_startup_checks

settings = get_settings()

docs_enabled = not (settings.ENV.lower() == "prod" and not settings.ENABLE_API_DOCS)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    install_redaction_filter()
    run_startup_checks(get_settings())
    yield


app = FastAPI(
    lifespan=lifespan,
    title=settings.APP_NAME,
    version="0.1.0",
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
)
# add_middleware wraps from the inside out; outermost first: headers, admin auth, CSRF cookie, request logging.
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(CsrfCookieMiddleware)
app.add_middleware(AdminAuthMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_exception_handler(
    HTTPException,
    http_exception_handler,  # type: ignore[arg-type]  # Starlette types handlers as Exception; gets HTTPException only
)
app.add_exception_handler(
    StarletteHTTPException,
    http_exception_handler,  # type: ignore[arg-type]  # Starlette types handlers as Exception; gets HTTPException only
)
app.add_exception_handler(Exception, server_exception_handler)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


admin_deps = [Depends(csrf_protect)]

app.include_router(home_routes.router, prefix="", dependencies=admin_deps)
app.include_router(api_ui_routes.router, dependencies=admin_deps)
app.include_router(quick_cert_routes.router, dependencies=admin_deps)
app.include_router(help_routes.router, dependencies=admin_deps)
app.include_router(setup_routes.router, dependencies=admin_deps)
app.include_router(cas_routes.router, dependencies=admin_deps)
app.include_router(certificates_routes.router, dependencies=admin_deps)
app.include_router(settings_routes.router, dependencies=admin_deps)
app.include_router(profiles_routes.router, dependencies=admin_deps)
app.include_router(api_routes.router)
app.include_router(notifications_routes.router, dependencies=admin_deps)
app.include_router(audit_routes.router, dependencies=admin_deps)
app.include_router(pki_routes.router)
app.include_router(workload_routes.router)
