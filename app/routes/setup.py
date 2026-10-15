from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.logging_config import logger
from app.models import ActorType, AuditStatus, CertificateAuthority
from app.schemas import ImportCAConfig, RootCAConfig
from app.services import keystore
from app.services.audit_service import log_action
from app.services.ca_service import create_root_ca, import_ca

router = APIRouter(tags=["setup"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/setup", response_class=HTMLResponse)
def setup_intro(request: Request, db: Session = Depends(get_db)) -> Response:
    if _has_existing_ca(db):
        return RedirectResponse(url="/cas", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "setup_wizard_step1.html", {"request": request})


@router.post("/setup/step1", response_class=HTMLResponse)
def setup_start(db: Session = Depends(get_db)) -> RedirectResponse:
    if _has_existing_ca(db):
        return RedirectResponse(url="/cas", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/setup/step2", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/setup/step2", response_class=HTMLResponse)
def setup_choose_source(request: Request, db: Session = Depends(get_db)) -> Response:
    if _has_existing_ca(db):
        return RedirectResponse(url="/cas", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request,
        "setup_wizard_step2.html",
        {"request": request, "error": None},
    )


@router.post("/setup/step2", response_class=HTMLResponse)
async def setup_choose_source_submit(request: Request, db: Session = Depends(get_db)) -> Response:
    if _has_existing_ca(db):
        return RedirectResponse(url="/cas", status_code=status.HTTP_303_SEE_OTHER)

    form = await request.form()
    choice = form.get("ca_source")
    if choice == "create":
        return RedirectResponse(url="/setup/root", status_code=status.HTTP_303_SEE_OTHER)
    if choice == "import":
        return RedirectResponse(url="/setup/import", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request,
        "setup_wizard_step2.html",
        {"request": request, "error": "Please select how you want to supply a CA."},
        status_code=status.HTTP_400_BAD_REQUEST,
    )


@router.get("/setup/root", response_class=HTMLResponse)
def setup_root_form(request: Request, db: Session = Depends(get_db)) -> Response:
    if _has_existing_ca(db):
        return RedirectResponse(url="/cas", status_code=status.HTTP_303_SEE_OTHER)
    defaults = {
        "name": "LabCA Root",
        "subject_cn": "LabCA Root",
        "subject_o": "",
        "subject_ou": "",
        "subject_c": "",
        "subject_st": "",
        "subject_l": "",
        "key_algorithm": "RSA",
        "key_size": "4096",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_years": "10",
        "path_length": "1",
        "download_cert": "true",
        "master_passphrase": "",
    }
    return templates.TemplateResponse(
        request,
        "setup_wizard_root.html",
        {"request": request, "form_values": defaults, "errors": []},
    )


@router.post("/setup/root", response_class=HTMLResponse)
async def setup_root_summary(request: Request, db: Session = Depends(get_db)) -> Response:
    if _has_existing_ca(db):
        return RedirectResponse(url="/cas", status_code=status.HTTP_303_SEE_OTHER)

    form = await request.form()
    data: Dict[str, Any] = {
        "name": _form_text(form, "name"),
        "subject_cn": _form_text(form, "subject_cn"),
        "subject_o": _blank_to_none(form.get("subject_o")),
        "subject_ou": _blank_to_none(form.get("subject_ou")),
        "subject_c": _blank_to_none(form.get("subject_c")),
        "subject_st": _blank_to_none(form.get("subject_st")),
        "subject_l": _blank_to_none(form.get("subject_l")),
        "key_algorithm": form.get("key_algorithm", "RSA"),
        "key_size": _safe_int(form.get("key_size")),
        "curve": form.get("curve") or None,
        "hash_algorithm": form.get("hash_algorithm", "SHA256"),
        "validity_years": _safe_int(form.get("validity_years")) or 5,
        "path_length": _safe_int(form.get("path_length")),
        "download_cert": form.get("download_cert") == "true",
        "master_passphrase": _blank_to_none(form.get("master_passphrase")),
    }

    errors = []
    try:
        config = RootCAConfig(**data)
    except Exception as exc:  # pydantic ValidationError
        errors.append(str(exc))
        return templates.TemplateResponse(
            request,
            "setup_wizard_root.html",
            {"request": request, "form_values": _form_to_dict(form), "errors": errors},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    payload = _encode_config(config.model_dump())
    return templates.TemplateResponse(
        request,
        "setup_wizard_summary.html",
        {
            "request": request,
            "mode": "create",
            "config": config,
            "config_data": config.model_dump(),
            "config_payload": payload,
            "title": "Review new Root CA",
        },
    )


@router.get("/setup/import", response_class=HTMLResponse)
def setup_import_form(request: Request, db: Session = Depends(get_db)) -> Response:
    if _has_existing_ca(db):
        return RedirectResponse(url="/cas", status_code=status.HTTP_303_SEE_OTHER)
    defaults = {
        "name": "",
        "cert_pem": "",
        "key_pem": "",
        "key_passphrase": "",
        "allow_intermediate_issuance": "",
        "master_passphrase": "",
    }
    return templates.TemplateResponse(
        request,
        "setup_wizard_import.html",
        {"request": request, "form_values": defaults, "errors": []},
    )


@router.post("/setup/import", response_class=HTMLResponse)
async def setup_import_summary(request: Request, db: Session = Depends(get_db)) -> Response:
    if _has_existing_ca(db):
        return RedirectResponse(url="/cas", status_code=status.HTTP_303_SEE_OTHER)

    form = await request.form()
    data: Dict[str, Any] = {
        "name": _form_text(form, "name"),
        "cert_pem": _form_text(form, "cert_pem"),
        "key_pem": _form_text(form, "key_pem"),
        "key_passphrase": _blank_to_none(form.get("key_passphrase")),
        "allow_intermediate_issuance": form.get("allow_intermediate_issuance") == "true",
        "master_passphrase": _blank_to_none(form.get("master_passphrase")),
    }
    errors = []
    try:
        config = ImportCAConfig(**data)
    except Exception as exc:
        errors.append(str(exc))
        return templates.TemplateResponse(
            request,
            "setup_wizard_import.html",
            {"request": request, "form_values": _form_to_dict(form), "errors": errors},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    payload = _encode_config(config.model_dump())
    return templates.TemplateResponse(
        request,
        "setup_wizard_summary.html",
        {
            "request": request,
            "mode": "import",
            "config": config,
            "config_data": config.model_dump(),
            "config_payload": payload,
            "title": "Review imported CA",
        },
    )


@router.post("/setup/complete")
async def setup_complete(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    mode = form.get("mode")
    payload = form.get("config_payload")
    if not mode or not payload:
        raise HTTPException(status_code=400, detail="Missing configuration payload.")

    data = _decode_config(cast(str, payload))
    try:
        if mode == "create":
            root_config = RootCAConfig(**data)
            ca = create_root_ca(root_config, db)
            action = "CREATE_CA"
        elif mode == "import":
            import_config = ImportCAConfig(**data)
            ca = import_ca(import_config, db)
            action = "IMPORT_CA"
        else:
            raise HTTPException(status_code=400, detail="Unknown setup mode.")
    except keystore.KeystoreError as exc:
        raise HTTPException(status_code=503, detail=f"Key storage is not configured: {exc}") from None

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_id="setup-wizard",
        action=action,
        target_type="CA",
        target_id=ca.id,
        status=AuditStatus.SUCCESS,
        ip_address=_client_ip(request),
        details={"ca_name": ca.name},
    )
    logger.info(
        "Setup wizard completed",
        extra={"ca_id": ca.id, "mode": mode},
    )

    return RedirectResponse(
        url=f"/cas/{ca.id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _has_existing_ca(db: Session) -> bool:
    return db.query(CertificateAuthority.id).first() is not None


def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _form_text(form: Any, key: str) -> str:
    # Form values are str for text inputs; file uploads are not expected for these fields.
    return cast(str, form.get(key, "")).strip()


def _blank_to_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _encode_config(data: Dict[str, Any]) -> str:
    json_data = json.dumps(data)
    return base64.b64encode(json_data.encode("utf-8")).decode("utf-8")


def _decode_config(payload: str) -> Dict[str, Any]:
    json_data = base64.b64decode(payload.encode("utf-8")).decode("utf-8")
    return json.loads(json_data)


def _form_to_dict(form) -> Dict[str, Any]:
    return {key: form.get(key) for key in form.keys()}


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None
