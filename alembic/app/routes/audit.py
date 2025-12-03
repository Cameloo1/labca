from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import AuditLog, ActorType
from app.templating import get_templates

router = APIRouter(prefix="/audit", tags=["audit"])
templates = get_templates()


@router.get("", response_class=HTMLResponse)
def audit_page(
    request: Request,
    start: Optional[str] = Query(default=None),
    end: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    actor: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = db.query(AuditLog).order_by(AuditLog.timestamp.desc())
    filters = {"start": start or "", "end": end or "", "action": action or "", "actor": actor or ""}

    if start:
        start_dt = _parse_datetime(start)
        query = query.filter(AuditLog.timestamp >= start_dt)
    if end:
        end_dt = _parse_datetime(end)
        query = query.filter(AuditLog.timestamp <= end_dt)
    if action:
        query = query.filter(AuditLog.action == action)
    if actor:
        query = query.filter(AuditLog.actor_id == actor)

    logs = query.limit(500).all()
    return templates.TemplateResponse(
        "audit.html",
        {
            "request": request,
            "logs": logs,
            "filters": filters,
            "actor_types": list(ActorType),
        },
    )


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid date filter.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
