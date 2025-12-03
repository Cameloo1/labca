from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import Profile


def list_profiles(db: Session, *, active_only: bool = False) -> List[Profile]:
    query = db.query(Profile).order_by(Profile.created_at.desc())
    if active_only:
        query = query.filter(Profile.active.is_(True))
    return query.all()


def get_profile(db: Session, profile_id: str) -> Optional[Profile]:
    return db.get(Profile, profile_id)


def create_profile(db: Session, data: Dict[str, Any]) -> Profile:
    profile = Profile(**data)
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


def update_profile(db: Session, profile: Profile, data: Dict[str, Any]) -> Profile:
    for key, value in data.items():
        if hasattr(profile, key):
            setattr(profile, key, value)
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile
