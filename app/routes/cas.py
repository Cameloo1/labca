from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session, selectinload

from app.dependencies import get_db
from app.logging_config import logger
from app.models import ActorType, AuditStatus, Certificate, CertificateAuthority, Profile
from app.schemas import IssueFromCAConfig
from app.services.audit_service import log_action
from app.services.cert_issuance_service import issue_cert_from_ca
from app.services.profile_service import get_profile, list_profiles
from app.templating import templates

router = APIRouter(prefix="/cas", tags=["cas"])


@router.get("", response_class=HTMLResponse)
def list_certificate_authorities(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    authorities = (
        db.query(CertificateAuthority)
        .options(selectinload(CertificateAuthority.certificates))
        .order_by(CertificateAuthority.created_at.asc())
        .all()
    )
    return templates.TemplateResponse(
        request,
        "cas_list.html",
        {"request": request, "authorities": authorities},
    )


@router.get("/{ca_id}", response_class=HTMLResponse)
def certificate_authority_detail(
    request: Request,
    ca_id: str,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    authority = (
        db.query(CertificateAuthority)
        .options(selectinload(CertificateAuthority.certificates))
        .filter(CertificateAuthority.id == ca_id)
        .one_or_none()
    )
    if authority is None:
        raise HTTPException(status_code=404, detail="Certificate Authority not found.")
    certificates = (
        db.query(Certificate).filter(Certificate.ca_id == ca_id).order_by(Certificate.created_at.desc()).all()
    )
    return templates.TemplateResponse(
        request,
        "cas_detail.html",
        {"request": request, "authority": authority, "certificates": certificates},
    )


@router.get("/{ca_id}/issue", response_class=HTMLResponse)
def issue_certificate_form(
    request: Request,
    ca_id: str,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    authority = db.get(CertificateAuthority, ca_id)
    if authority is None:
        raise HTTPException(status_code=404, detail="Certificate Authority not found.")

    defaults = {
        "common_name": "",
        "organization": "",
        "organizational_unit": "",
        "country": "",
        "state": "",
        "locality": "",
        "dns_sans": "",
        "ip_sans": "",
        "uri_sans": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "365",
        "usage_preset": "server_tls",
        "is_ca": "false",
        "store_in_db": "true",
        "environment_tags": "",
        "owner": "",
        "enable_expiration_reminders": "",
    }
    profile_id = request.query_params.get("profile_id")
    active_profile: Profile | None = None
    if profile_id:
        candidate = get_profile(db, profile_id)
        if candidate and candidate.active:
            active_profile = candidate
            defaults = _apply_profile_defaults(candidate, defaults)
    profiles = list_profiles(db, active_only=True)
    context = {
        "request": request,
        "authority": authority,
        "form_values": defaults,
        "errors": [],
        "validity_limit": _validity_limit_days(authority),
        "profiles": profiles,
        "active_profile": active_profile,
    }
    return templates.TemplateResponse(request, "issue_from_ca.html", context)


@router.post("/{ca_id}/issue", response_class=HTMLResponse)
async def issue_certificate_submit(
    request: Request,
    ca_id: str,
    db: Session = Depends(get_db),
):
    authority = db.get(CertificateAuthority, ca_id)
    if authority is None:
        raise HTTPException(status_code=404, detail="Certificate Authority not found.")

    form = await request.form()
    cleaned = _form_to_dict(form)
    dns_sans = _split_csv(cleaned.get("dns_sans", ""))
    ip_sans = _split_csv(cleaned.get("ip_sans", ""))
    uri_sans = _split_csv(cleaned.get("uri_sans", ""))
    env_tags = _split_csv(cleaned.get("environment_tags", ""))
    store_in_db = cleaned.get("store_in_db") == "true" or cleaned.get("store_in_db") == "on"

    payload = {
        "issuer_ca_id": authority.id,
        "common_name": cleaned.get("common_name", "").strip(),
        "organization": _blank_to_none(cleaned.get("organization")),
        "organizational_unit": _blank_to_none(cleaned.get("organizational_unit")),
        "country": _blank_to_none(cleaned.get("country")),
        "state": _blank_to_none(cleaned.get("state")),
        "locality": _blank_to_none(cleaned.get("locality")),
        "dns_sans": dns_sans,
        "ip_sans": ip_sans,
        "uri_sans": uri_sans,
        "key_algorithm": cleaned.get("key_algorithm", "RSA"),
        "key_size": _safe_int(cleaned.get("key_size")) or 2048,
        "curve": cleaned.get("curve") or "P-256",
        "hash_algorithm": cleaned.get("hash_algorithm", "SHA256"),
        "validity_days": _safe_int(cleaned.get("validity_days")) or 365,
        "usage_preset": cleaned.get("usage_preset", "server_tls"),
        "is_ca": cleaned.get("is_ca") == "true",
        "store_in_db": store_in_db,
        "environment_tags": env_tags,
        "owner": _blank_to_none(cleaned.get("owner")),
        "enable_expiration_reminders": cleaned.get("enable_expiration_reminders") == "on",
    }

    errors = []
    try:
        config = IssueFromCAConfig(**payload)
    except Exception as exc:
        errors.append(str(exc))
        return templates.TemplateResponse(
            request,
            "issue_from_ca.html",
            {
                "request": request,
                "authority": authority,
                "form_values": cleaned,
                "errors": errors,
                "validity_limit": _validity_limit_days(authority),
                "profiles": list_profiles(db, active_only=True),
                "active_profile": None,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    try:
        certificate = issue_cert_from_ca(config, authority, db)
    except ValueError as exc:
        errors.append(str(exc))
        return templates.TemplateResponse(
            request,
            "issue_from_ca.html",
            {
                "request": request,
                "authority": authority,
                "form_values": cleaned,
                "errors": errors,
                "validity_limit": _validity_limit_days(authority),
                "profiles": list_profiles(db, active_only=True),
                "active_profile": None,
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_id="web-ui",
        action="ISSUE_CERT",
        target_type="CERTIFICATE",
        target_id=certificate.id,
        status=AuditStatus.SUCCESS,
        ip_address=_client_ip(request),
        details={
            "issuer_ca_id": authority.id,
            "common_name": certificate.common_name,
        },
    )
    logger.info(
        "Certificate issued from CA",
        extra={"certificate_id": certificate.id, "issuer_ca_id": authority.id},
    )

    return RedirectResponse(
        url=f"/certificates/{certificate.id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{ca_id}/download-cert")
def download_ca_certificate(ca_id: str, db: Session = Depends(get_db)) -> PlainTextResponse:
    authority = db.get(CertificateAuthority, ca_id)
    if authority is None:
        raise HTTPException(status_code=404, detail="Certificate Authority not found.")

    filename = f"{authority.name.lower().replace(' ', '_')}_ca.crt"
    return PlainTextResponse(
        authority.cert_pem,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _validity_limit_days(ca: CertificateAuthority) -> int:
    if not ca.not_after:
        return 365
    now = datetime.now(timezone.utc)
    delta = _as_aware(ca.not_after) - now
    return max(delta.days, 1)


def _form_to_dict(form) -> dict:
    return {key: form.get(key) for key in form.keys()}


def _split_csv(value: str) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _blank_to_none(value):
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _apply_profile_defaults(profile: Profile, defaults: dict) -> dict:
    subject = profile.subject_template or {}
    defaults.update(
        {
            "common_name": subject.get("CN", defaults["common_name"]),
            "organization": subject.get("O", defaults["organization"]),
            "organizational_unit": subject.get("OU", defaults["organizational_unit"]),
            "country": subject.get("C", defaults["country"]),
            "state": subject.get("ST", defaults["state"]),
            "locality": subject.get("L", defaults["locality"]),
            "key_algorithm": profile.key_algorithm,
            "key_size": str(profile.key_size),
            "validity_days": str(profile.validity_days_default),
            "store_in_db": "true" if profile.store_in_db_default else "false",
            "environment_tags": ",".join(profile.environment_tags_default or []),
            "owner": profile.owner_default or "",
        }
    )
    usage = profile.usage_config_json or {}
    if usage.get("is_ca"):
        defaults["is_ca"] = "true"
    eku = usage.get("extended_key_usage") or []
    if "clientAuth" in eku and "serverAuth" not in eku:
        defaults["usage_preset"] = "client_tls"
    elif "serverAuth" in eku:
        defaults["usage_preset"] = "server_tls"
    return defaults


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None
