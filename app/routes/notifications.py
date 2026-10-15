from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.services.notification_service import ensure_default_rules, update_rules
from app.templating import templates

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_class=HTMLResponse)
def notifications_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    rules = ensure_default_rules(db)
    message = request.query_params.get("message")
    messages = [message] if message else []
    return templates.TemplateResponse(
        request,
        "notifications.html",
        {
            "request": request,
            "rules": rules,
            "messages": messages,
        },
    )


@router.post("")
async def update_notifications(
    request: Request,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    form = await request.form()
    rules = ensure_default_rules(db)
    updates = []
    for rule in rules:
        enabled = _checkbox_checked(form, f"rule-{rule.id}-enabled")
        email = _checkbox_checked(form, f"rule-{rule.id}-email")
        webhook = _checkbox_checked(form, f"rule-{rule.id}-webhook")
        delivery_methods = {
            "email": email,
            "webhook": webhook,
        }
        updates.append((rule.id, enabled, delivery_methods))

    update_rules(db, updates)
    return RedirectResponse(
        url="/notifications?message=Notification+rules+updated.",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _checkbox_checked(form, key: str) -> bool:
    value = form.get(key)
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "on", "yes"}
