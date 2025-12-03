from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db
from app.schemas import TokenPermissions
from app.services.api_token_service import create_token, list_tokens

router = APIRouter(tags=["api-ui"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/api", response_class=HTMLResponse)
def api_portal(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    return _render_page(request, db, _default_form_values(), [])


@router.post("/api", response_class=HTMLResponse)
async def api_portal_create_token(
    request: Request,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    form = await request.form()
    form_values = _extract_form_values(form)
    errors: list[str] = []
    messages: list[str] = []
    created_token_value: str | None = None

    settings = get_settings()
    creation_secret = settings.API_TOKEN_CREATION_SECRET
    if not creation_secret:
        errors.append("Token creation is disabled. Set API_TOKEN_CREATION_SECRET to use this form.")
    elif form_values["admin_secret"] != creation_secret:
        errors.append("Admin secret is incorrect.")

    if not form_values["name"].strip():
        errors.append("Token name is required.")

    expires_at = None
    if form_values["expires_at"]:
        try:
            expires_at = _parse_datetime_local(form_values["expires_at"])
        except ValueError:
            errors.append("Expiration must be in ISO format (YYYY-MM-DDTHH:MM).")

    if not errors:
        permissions = {
            "issue": form_values["perm_issue"],
            "read": form_values["perm_read"],
            "revoke": form_values["perm_revoke"],
        }
        token, raw_value = create_token(form_values["name"], permissions, expires_at, db)
        created_token_value = raw_value
        messages.append("API token created. Copy the value now—it will not be shown again.")
        form_values = _default_form_values()
        form_values["perm_issue"] = permissions["issue"]
        form_values["perm_read"] = permissions["read"]
        form_values["perm_revoke"] = permissions["revoke"]

    return _render_page(
        request,
        db,
        form_values,
        errors,
        messages=messages,
        created_token_value=created_token_value,
        status_code=status.HTTP_400_BAD_REQUEST if errors else status.HTTP_200_OK,
    )


def _render_page(
    request: Request,
    db: Session,
    form_values: Dict[str, Any],
    errors: list[str],
    *,
    messages: list[str] | None = None,
    created_token_value: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    tokens = [
        {
            "id": token.id,
            "name": token.name,
            "token_prefix": token.token_prefix,
            "permissions": TokenPermissions(**(token.permissions_json or {})),
            "expires_at": token.expires_at,
            "last_used_at": token.last_used_at,
            "created_at": token.created_at,
        }
        for token in list_tokens(db)
    ]
    settings = get_settings()
    context = {
        "request": request,
        "tokens": tokens,
        "form_values": form_values,
        "form_errors": errors,
        "messages": messages or [],
        "created_token_value": created_token_value,
        "creation_enabled": bool(settings.API_TOKEN_CREATION_SECRET),
    }
    return templates.TemplateResponse("api.html", context, status_code=status_code)


def _default_form_values() -> Dict[str, Any]:
    return {
        "name": "",
        "perm_issue": True,
        "perm_read": True,
        "perm_revoke": False,
        "expires_at": "",
        "admin_secret": "",
    }


def _extract_form_values(form: Any) -> Dict[str, Any]:
    values = _default_form_values()
    values["name"] = form.get("name", "").strip()
    values["perm_issue"] = _to_bool(form.get("perm_issue", "on"))
    values["perm_read"] = _to_bool(form.get("perm_read", "on"))
    values["perm_revoke"] = _to_bool(form.get("perm_revoke", ""))
    values["expires_at"] = form.get("expires_at", "")
    values["admin_secret"] = form.get("admin_secret", "")
    return values


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "on", "yes"}


def _parse_datetime_local(raw_value: str) -> datetime:
    parsed = datetime.fromisoformat(raw_value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
