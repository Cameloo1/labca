from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import CertificateAuthority, ProfileType
from app.services.profile_service import create_profile, get_profile, list_profiles, update_profile
from app.templating import templates

router = APIRouter(prefix="/profiles", tags=["profiles"])


@router.get("", response_class=HTMLResponse)
def profiles_list(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    profiles = list_profiles(db)
    authorities = db.query(CertificateAuthority).order_by(CertificateAuthority.name).all()
    return templates.TemplateResponse(
        request,
        "profiles_list.html",
        {"request": request, "profiles": profiles, "authorities": authorities},
    )


@router.get("/new", response_class=HTMLResponse)
def new_profile_form(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    authorities = db.query(CertificateAuthority).order_by(CertificateAuthority.name).all()
    form_values = _default_form_values()
    return templates.TemplateResponse(
        request,
        "profile_form.html",
        {
            "request": request,
            "form_values": form_values,
            "authorities": authorities,
            "profile_types": list(ProfileType),
            "mode": "create",
        },
    )


@router.post("/new")
async def create_profile_submit(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    form = await request.form()
    data = _form_to_profile_payload(form)
    create_profile(db, data)
    return RedirectResponse("/profiles", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{profile_id}/edit", response_class=HTMLResponse)
def edit_profile_form(profile_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    profile = get_profile(db, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found.")
    authorities = db.query(CertificateAuthority).order_by(CertificateAuthority.name).all()
    form_values = _profile_to_form_values(profile)
    return templates.TemplateResponse(
        request,
        "profile_form.html",
        {
            "request": request,
            "form_values": form_values,
            "authorities": authorities,
            "profile_types": list(ProfileType),
            "mode": "edit",
            "profile": profile,
        },
    )


@router.post("/{profile_id}/edit")
async def edit_profile_submit(profile_id: str, request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    profile = get_profile(db, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found.")
    form = await request.form()
    data = _form_to_profile_payload(form)
    update_profile(db, profile, data)
    return RedirectResponse("/profiles", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{profile_id}/clone")
def clone_profile(profile_id: str, db: Session = Depends(get_db)) -> RedirectResponse:
    profile = get_profile(db, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found.")
    payload = _profile_to_form_values(profile)
    payload["name"] = f"{payload['name']} Copy"
    data = _form_values_to_model(payload)
    new_profile = create_profile(db, data)
    return RedirectResponse(f"/profiles/{new_profile.id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{profile_id}/toggle-active")
def toggle_profile_active(profile_id: str, db: Session = Depends(get_db)) -> RedirectResponse:
    profile = get_profile(db, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found.")
    profile.active = not profile.active
    update_profile(db, profile, {})
    return RedirectResponse("/profiles", status_code=status.HTTP_303_SEE_OTHER)


def _default_form_values() -> dict:
    return {
        "name": "",
        "description": "",
        "profile_type": ProfileType.SERVER_TLS.value,
        "default_issuer_ca_id": "",
        "subject_cn": "",
        "subject_o": "",
        "subject_ou": "",
        "subject_c": "",
        "subject_st": "",
        "subject_l": "",
        "key_algorithm": "RSA",
        "key_size": 2048,
        "validity_days_default": 365,
        "validity_days_min": "",
        "validity_days_max": "",
        "usage_config_json": json.dumps(
            {
                "is_ca": False,
                "key_usage": {"digital_signature": True, "key_encipherment": True},
                "extended_key_usage": ["serverAuth"],
                "path_length": None,
            },
            indent=2,
        ),
        "output_config_json": json.dumps(
            {
                "output_pem_cert": True,
                "output_pem_key": True,
                "output_combined_pem": False,
                "output_pfx": False,
            },
            indent=2,
        ),
        "store_in_db_default": True,
        "environment_tags_default": "",
        "owner_default": "",
        "available_in_simple_mode": False,
        "active": True,
    }


def _form_to_profile_payload(form) -> dict:
    env_tags = _split_csv(form.get("environment_tags_default", ""))
    data = {
        "name": form.get("name", "").strip(),
        "description": form.get("description", "").strip() or None,
        "profile_type": ProfileType(form.get("profile_type", ProfileType.SERVER_TLS.value)),
        "default_issuer_ca_id": form.get("default_issuer_ca_id") or None,
        "subject_template": {
            "CN": form.get("subject_cn", "").strip(),
            "O": form.get("subject_o", "").strip(),
            "OU": form.get("subject_ou", "").strip(),
            "C": form.get("subject_c", "").strip(),
            "ST": form.get("subject_st", "").strip(),
            "L": form.get("subject_l", "").strip(),
        },
        "key_algorithm": form.get("key_algorithm", "RSA"),
        "key_size": int(form.get("key_size") or 2048),
        "validity_days_default": int(form.get("validity_days_default") or 365),
        "validity_days_min": _safe_int(form.get("validity_days_min")),
        "validity_days_max": _safe_int(form.get("validity_days_max")),
        "usage_config_json": _safe_json(form.get("usage_config_json"), {}),
        "output_config_json": _safe_json(form.get("output_config_json"), {}),
        "store_in_db_default": form.get("store_in_db_default") == "on",
        "environment_tags_default": env_tags,
        "owner_default": form.get("owner_default", "").strip() or None,
        "available_in_simple_mode": form.get("available_in_simple_mode") == "on",
        "active": form.get("active") == "on",
    }
    return data


def _profile_to_form_values(profile) -> dict:
    defaults = _default_form_values()
    defaults.update(
        {
            "name": profile.name,
            "description": profile.description or "",
            "profile_type": profile.profile_type.value,
            "default_issuer_ca_id": profile.default_issuer_ca_id or "",
            "subject_cn": profile.subject_template.get("CN", ""),
            "subject_o": profile.subject_template.get("O", ""),
            "subject_ou": profile.subject_template.get("OU", ""),
            "subject_c": profile.subject_template.get("C", ""),
            "subject_st": profile.subject_template.get("ST", ""),
            "subject_l": profile.subject_template.get("L", ""),
            "key_algorithm": profile.key_algorithm,
            "key_size": profile.key_size,
            "validity_days_default": profile.validity_days_default,
            "validity_days_min": profile.validity_days_min or "",
            "validity_days_max": profile.validity_days_max or "",
            "usage_config_json": json.dumps(profile.usage_config_json, indent=2),
            "output_config_json": json.dumps(profile.output_config_json, indent=2),
            "store_in_db_default": profile.store_in_db_default,
            "environment_tags_default": ",".join(profile.environment_tags_default or []),
            "owner_default": profile.owner_default or "",
            "available_in_simple_mode": profile.available_in_simple_mode,
            "active": profile.active,
        }
    )
    return defaults


def _form_values_to_model(values: dict) -> dict:
    fake_form = {key: str(value) for key, value in values.items()}
    return _form_to_profile_payload(fake_form)


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_json(value: str | None, fallback: dict) -> dict:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _split_csv(value: str) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]
