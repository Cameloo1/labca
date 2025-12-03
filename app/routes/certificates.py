from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, selectinload

from app.dependencies import get_db
from app.models import (
    AllowKeyDownloadPolicy,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
    ActorType,
    AuditStatus,
)
from app.logging_config import logger
from app.services.revocation_service import revoke_certificate
from app.services.audit_service import log_action
from app.services.settings_service import get_app_settings

router = APIRouter(prefix="/certificates", tags=["certificates"])
templates = Jinja2Templates(directory="app/templates")

QUICK_EXPIRY_FILTERS = (7, 30, 90)
REVOCATION_REASONS = [
    ("key_compromise", "Key compromise"),
    ("ca_compromise", "CA compromise"),
    ("superseded", "Superseded"),
    ("cessation_of_operation", "Cessation of operation"),
    ("affiliation_changed", "Affiliation changed"),
    ("unspecified", "Unspecified"),
]


@router.get("", response_class=HTMLResponse)
def list_certificates(
    request: Request,
    search: Optional[str] = Query(default=None),
    issuer_ca_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    expiry_filter: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    query = (
        db.query(Certificate)
        .options(selectinload(Certificate.ca))
        .order_by(Certificate.not_after.desc())
    )

    if issuer_ca_id:
        query = query.filter(Certificate.ca_id == issuer_ca_id)

    certificates = query.all()
    now = datetime.now(timezone.utc)

    status_filter: Optional[CertificateStatusEnum] = None
    if status:
        try:
            status_filter = CertificateStatusEnum(status.upper())
        except ValueError as exc:  # pragma: no cover - defensive
            raise HTTPException(status_code=400, detail="Invalid status filter.") from exc

    expiry_days: Optional[int] = None
    if expiry_filter:
        try:
            parsed_filter = int(expiry_filter)
        except ValueError as exc:  # pragma: no cover - defensive
            raise HTTPException(status_code=400, detail="Invalid expiry filter.") from exc
        if parsed_filter not in QUICK_EXPIRY_FILTERS:
            raise HTTPException(status_code=400, detail="Invalid expiry filter.")
        expiry_days = parsed_filter

    expiry_deadline = now + timedelta(days=expiry_days) if expiry_days else None

    search_value = search.lower().strip() if search else None

    certificate_rows = []
    for cert in certificates:
        computed_status = cert.compute_status(now)

        if status_filter and computed_status != status_filter:
            continue

        if expiry_deadline:
            if computed_status != CertificateStatusEnum.ACTIVE:
                continue
            not_after = _as_aware(cert.not_after)
            if not (now <= not_after <= expiry_deadline):
                continue

        if search_value:
            haystacks = [
                cert.common_name or "",
                cert.serial_number or "",
                " ".join(cert.san_dns or []),
                " ".join(cert.san_ips or []),
            ]
            if not any(search_value in value.lower() for value in haystacks if value):
                continue

        certificate_rows.append({"certificate": cert, "status": computed_status})

    issuer_options: List[CertificateAuthority] = (
        db.query(CertificateAuthority)
        .order_by(CertificateAuthority.name.asc())
        .all()
    )

    return templates.TemplateResponse(
        "certificates_list.html",
        {
            "request": request,
            "certificates": certificate_rows,
            "filters": {
                "search": search or "",
                "issuer_ca_id": issuer_ca_id or "",
                "status": status_filter.value if status_filter else "",
                "expiry_filter": expiry_days or "",
            },
            "status_options": list(CertificateStatusEnum),
            "issuer_options": issuer_options,
            "quick_expiry_options": QUICK_EXPIRY_FILTERS,
        },
    )


@router.get("/{cert_id}", response_class=HTMLResponse)
def certificate_detail(cert_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    certificate = _get_certificate(db, cert_id)
    computed_status = certificate.compute_status()
    app_settings = get_app_settings(db)
    key_download_allowed = _is_key_download_allowed(certificate, app_settings.allow_key_download_policy)
    message = request.query_params.get("message")
    messages = [message] if message else []
    return templates.TemplateResponse(
        "certificate_detail.html",
        {
            "request": request,
            "certificate": certificate,
            "computed_status": computed_status,
            "messages": messages,
            "key_download_allowed": key_download_allowed,
        },
    )


@router.get("/{cert_id}/download-cert")
def download_certificate(cert_id: str, db: Session = Depends(get_db)) -> PlainTextResponse:
    certificate = db.get(Certificate, cert_id)
    if certificate is None:
        raise HTTPException(status_code=404, detail="Certificate not found.")
    filename = f"{certificate.common_name.replace(' ', '_')}.crt"
    return PlainTextResponse(
        certificate.cert_pem,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{cert_id}/download-key")
def download_certificate_key(cert_id: str, db: Session = Depends(get_db)) -> PlainTextResponse:
    certificate = _get_certificate(db, cert_id)
    if not certificate.stored_key_encrypted_pem:
        raise HTTPException(status_code=404, detail="Private key not stored for this certificate.")
    app_settings = get_app_settings(db)
    if not _is_key_download_allowed(certificate, app_settings.allow_key_download_policy):
        raise HTTPException(status_code=403, detail="Private key downloads are disabled by policy.")
    key_bytes = _decode_encrypted_pem(certificate.stored_key_encrypted_pem)
    filename = f"{certificate.common_name.replace(' ', '_')}.key"
    return PlainTextResponse(
        key_bytes.decode("utf-8"),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{cert_id}/download-chain")
def download_certificate_chain(cert_id: str, db: Session = Depends(get_db)) -> PlainTextResponse:
    certificate = _get_certificate(db, cert_id)
    if certificate.ca is None:
        raise HTTPException(status_code=404, detail="Issuer information missing.")
    chain = f"{certificate.cert_pem}\n{certificate.ca.cert_pem}"
    filename = f"{certificate.common_name.replace(' ', '_')}_chain.pem"
    return PlainTextResponse(
        chain,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{cert_id}/revoke", response_class=HTMLResponse)
def revoke_certificate_form(cert_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    certificate = _get_certificate(db, cert_id)
    computed_status = certificate.compute_status()
    if computed_status == CertificateStatusEnum.REVOKED:
        return RedirectResponse(
            url=f"/certificates/{cert_id}?message=Certificate+is+already+revoked.",
            status_code=303,
        )
    return templates.TemplateResponse(
        "certificate_revoke.html",
        {
            "request": request,
            "certificate": certificate,
            "computed_status": computed_status,
            "revocation_reasons": REVOCATION_REASONS,
        },
    )


@router.post("/{cert_id}/revoke")
async def revoke_certificate_submit(
    cert_id: str,
    request: Request,
    reason_code: str = Form(...),
    notes: Optional[str] = Form(default=None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    certificate = _get_certificate(db, cert_id)
    if certificate.compute_status() == CertificateStatusEnum.REVOKED:
        return RedirectResponse(
            url=f"/certificates/{cert_id}?message=Certificate+is+already+revoked.",
            status_code=303,
        )
    reason_label = _resolve_reason_label(reason_code)
    reason_text = reason_label
    if notes:
        cleaned = notes.strip()
        if cleaned:
            reason_text = f"{reason_label} - {cleaned}"
    reason_text = reason_text[:255]
    revoke_certificate(certificate, reason_text, db)
    log_action(
        db,
        actor_type=ActorType.USER,
        actor_id="web-ui",
        action="REVOKE_CERT",
        target_type="CERTIFICATE",
        target_id=certificate.id,
        status=AuditStatus.SUCCESS,
        ip_address=_client_ip(request),
        details={"reason": reason_label, "certificate_cn": certificate.common_name},
    )
    logger.info(
        "Certificate revoked",
        extra={"certificate_id": certificate.id, "reason": reason_label},
    )
    return RedirectResponse(
        url=f"/certificates/{cert_id}?message=Certificate+revoked+successfully.",
        status_code=303,
    )


def _decode_encrypted_pem(value: str) -> bytes:
    if value.startswith("enc::"):
        value = value[len("enc::") :]
    return base64.b64decode(value.encode("utf-8"))


def _as_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_certificate(db: Session, cert_id: str) -> Certificate:
    certificate = (
        db.query(Certificate)
        .options(selectinload(Certificate.ca))
        .filter(Certificate.id == cert_id)
        .one_or_none()
    )
    if certificate is None:
        raise HTTPException(status_code=404, detail="Certificate not found.")
    return certificate


def _resolve_reason_label(reason_code: str) -> str:
    lookup = {value: label for value, label in REVOCATION_REASONS}
    if reason_code not in lookup:
        raise HTTPException(status_code=400, detail="Invalid revocation reason.")
    return lookup[reason_code]


def _is_key_download_allowed(certificate: Certificate, policy: AllowKeyDownloadPolicy) -> bool:
    if policy == AllowKeyDownloadPolicy.ALL:
        return True
    if policy == AllowKeyDownloadPolicy.NONE:
        return False
    if policy == AllowKeyDownloadPolicy.LEAF_ONLY:
        return certificate.type == CertificateTypeEnum.LEAF
    if policy == AllowKeyDownloadPolicy.CA_DISABLED:
        return certificate.type != CertificateTypeEnum.INTERMEDIATE
    return True


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None
