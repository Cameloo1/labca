from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.logging_config import logger
from app.models import ActorType, AllowKeyDownloadPolicy, AuditStatus
from app.services.audit_service import log_action
from app.services.settings_service import get_app_settings, update_app_settings
from app.templating import templates

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    settings = get_app_settings(db)
    message = request.query_params.get("message")
    messages = [message] if message else []
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "request": request,
            "settings": settings,
            "messages": messages,
            "policy_options": list(AllowKeyDownloadPolicy),
        },
    )


@router.post("")
async def update_settings(
    request: Request,
    app_name: str = Form(default=""),
    default_key_algorithm: str = Form(...),
    default_key_size: int = Form(...),
    default_validity_days: int = Form(...),
    max_leaf_validity_days: int = Form(...),
    allow_key_download_policy: str = Form(...),
    require_login: str | None = Form(default=None),
    allow_intermediate_issuance: str | None = Form(default=None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    try:
        policy = AllowKeyDownloadPolicy(allow_key_download_policy)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid key download policy.") from exc

    payload = {
        "app_name": app_name.strip() or None,
        "default_key_algorithm": default_key_algorithm,
        "default_key_size": int(default_key_size),
        "default_validity_days": int(default_validity_days),
        "max_leaf_validity_days": int(max_leaf_validity_days),
        "allow_key_download_policy": policy,
        "require_login": require_login is not None,
        "allow_intermediate_issuance": allow_intermediate_issuance is not None,
    }
    update_app_settings(db, payload)
    log_action(
        db,
        actor_type=ActorType.USER,
        actor_id="web-ui",
        action="UPDATE_SETTINGS",
        target_type="SETTINGS",
        target_id="app",
        status=AuditStatus.SUCCESS,
        ip_address=_client_ip(request),
        details={
            "app_name": payload["app_name"],
            "default_key_algorithm": payload["default_key_algorithm"],
            "default_validity_days": payload["default_validity_days"],
        },
    )
    logger.info(
        "Settings updated",
        extra={
            "app_name": payload["app_name"],
            "default_key_algorithm": payload["default_key_algorithm"],
        },
    )
    return RedirectResponse(
        url="/settings?message=Settings+updated.",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None
