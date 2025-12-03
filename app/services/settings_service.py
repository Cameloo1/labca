from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.orm import Session

from app.models import AllowKeyDownloadPolicy, AppSettings

DEFAULT_SETTINGS: Dict[str, Any] = {
    "id": 1,
    "app_name": "LabCA",
    "default_key_algorithm": "RSA",
    "default_key_size": 2048,
    "default_validity_days": 365,
    "max_leaf_validity_days": 825,
    "allow_key_download_policy": AllowKeyDownloadPolicy.ALL,
    "require_login": False,
    "key_storage_encryption_enabled": True,
    "allow_intermediate_issuance": True,
}


def get_app_settings(db: Session) -> AppSettings:
    settings = db.get(AppSettings, 1)
    if settings is None:
        settings = AppSettings(**DEFAULT_SETTINGS)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def update_app_settings(db: Session, data: Dict[str, Any]) -> AppSettings:
    settings = get_app_settings(db)
    for key, value in data.items():
        if hasattr(settings, key):
            setattr(settings, key, value)
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return settings
