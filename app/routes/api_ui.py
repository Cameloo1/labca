from __future__ import annotations

import hmac
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db
from app.schemas import TokenPermissions, TokenPolicy
from app.services.api_token_service import create_token, list_tokens
from app.templating import templates

router = APIRouter(tags=["api-ui"])


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
    elif not hmac.compare_digest(form_values["admin_secret"].encode(), creation_secret.encode()):
        errors.append("Admin secret is incorrect.")

    if not form_values["name"].strip():
        errors.append("Token name is required.")

    expires_at = None
    if form_values["expires_at"]:
        try:
            expires_at = _parse_datetime_local(form_values["expires_at"])
        except ValueError:
            errors.append("Expiration must be in ISO format (YYYY-MM-DDTHH:MM).")

    policy: TokenPolicy | None = None
    if form_values["policy_enabled"]:
        policy, policy_errors = _build_policy(form_values)
        errors.extend(policy_errors)

    if not errors:
        permissions = {
            "issue": form_values["perm_issue"],
            "read": form_values["perm_read"],
            "revoke": form_values["perm_revoke"],
        }
        token, raw_value = create_token(
            form_values["name"],
            permissions,
            expires_at,
            db,
            policy=policy.model_dump() if policy else None,
        )
        created_token_value = raw_value
        messages.append("API token created. Copy the value now. It will not be shown again.")
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
            "policy_summary": _policy_summary(token.policy_json),
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
    return templates.TemplateResponse(request, "api.html", context, status_code=status_code)


def _default_form_values() -> Dict[str, Any]:
    return {
        "name": "",
        "perm_issue": True,
        "perm_read": True,
        "perm_revoke": False,
        "expires_at": "",
        "admin_secret": "",
        "policy_enabled": False,
        "policy_dns_suffixes": "",
        "policy_uri_prefixes": "",
        "policy_max_validity_hours": "2160",
        "policy_revoke_any": False,
    }


def _extract_form_values(form: Any) -> Dict[str, Any]:
    values = _default_form_values()
    values["name"] = form.get("name", "").strip()
    values["perm_issue"] = _to_bool(form.get("perm_issue", "on"))
    values["perm_read"] = _to_bool(form.get("perm_read", "on"))
    values["perm_revoke"] = _to_bool(form.get("perm_revoke", ""))
    values["expires_at"] = form.get("expires_at", "")
    values["admin_secret"] = form.get("admin_secret", "")
    values["policy_enabled"] = _to_bool(form.get("policy_enabled", ""))
    values["policy_dns_suffixes"] = form.get("policy_dns_suffixes", "")
    values["policy_uri_prefixes"] = form.get("policy_uri_prefixes", "")
    values["policy_max_validity_hours"] = form.get("policy_max_validity_hours", "2160")
    values["policy_revoke_any"] = _to_bool(form.get("policy_revoke_any", ""))
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


def _split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _build_policy(form_values: Dict[str, Any]) -> tuple[TokenPolicy | None, list[str]]:
    try:
        max_hours = int(str(form_values["policy_max_validity_hours"]).strip())
    except ValueError:
        return None, ["Policy maximum validity must be a whole number of hours."]
    try:
        policy = TokenPolicy(
            allowed_dns_suffixes=_split_csv(form_values["policy_dns_suffixes"]),
            allowed_uri_prefixes=_split_csv(form_values["policy_uri_prefixes"]),
            max_validity_hours=max_hours,
            revoke_any=form_values["policy_revoke_any"],
        )
    except ValidationError as exc:
        messages = [str(err["msg"]).removeprefix("Value error, ") for err in exc.errors()]
        return None, [f"Invalid policy: {message}" for message in messages]
    return policy, []


def _policy_summary(policy_json: Dict[str, Any] | None) -> str | None:
    if policy_json is None:
        return None
    policy = TokenPolicy.model_validate(policy_json)
    parts: list[str] = []
    if policy.allowed_dns_suffixes:
        parts.append("DNS: " + ", ".join(policy.allowed_dns_suffixes))
    if policy.allowed_uri_prefixes:
        parts.append("URI: " + ", ".join(policy.allowed_uri_prefixes))
    parts.append(f"max {policy.max_validity_hours}h")
    if policy.revoke_any:
        parts.append("revoke any")
    return "; ".join(parts)
