from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models import ActorType, AuditLog, AuditStatus


def log_action(
    db: Session,
    *,
    actor_type: ActorType,
    actor_id: Optional[str],
    action: str,
    target_type: str,
    target_id: Optional[str],
    status: AuditStatus = AuditStatus.SUCCESS,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    log = AuditLog(
        timestamp=datetime.now(timezone.utc),
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        status=status,
        ip_address=ip_address,
        details_json=details or {},
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log
