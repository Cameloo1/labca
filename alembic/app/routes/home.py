from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session, selectinload

from app.config import get_settings
from app.dependencies import get_db
from app.models import Certificate, CertificateAuthority, CertificateStatusEnum, Profile
from app.templating import get_templates

router = APIRouter(tags=["home"])

templates = get_templates()
settings = get_settings()


@router.get("/", response_class=HTMLResponse)
def get_home(
    request: Request,
    search: Optional[str] = Query(default=None),
    issuer_ca_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    expiry_filter: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    profiles = (
        db.query(Profile)
        .options(selectinload(Profile.default_issuer))
        .order_by(Profile.created_at.desc())
        .all()
    )
    
    # Fetch certificate authorities with their certificates
    authorities = (
        db.query(CertificateAuthority)
        .options(selectinload(CertificateAuthority.certificates))
        .order_by(CertificateAuthority.created_at.asc())
        .all()
    )
    
    # Fetch certificates with their CAs
    certificates_query = (
        db.query(Certificate)
        .options(selectinload(Certificate.ca))
        .order_by(Certificate.not_after.desc())
    )
    
    if issuer_ca_id:
        certificates_query = certificates_query.filter(Certificate.ca_id == issuer_ca_id)
    
    certificates_list = certificates_query.all()
    now = datetime.now(timezone.utc)
    
    # Apply filters
    status_filter: Optional[CertificateStatusEnum] = None
    if status:
        try:
            status_filter = CertificateStatusEnum(status.upper())
        except ValueError:
            status_filter = None
    
    expiry_days: Optional[int] = None
    if expiry_filter:
        try:
            parsed_filter = int(expiry_filter)
            if parsed_filter in (7, 30, 90):
                expiry_days = parsed_filter
        except ValueError:
            expiry_days = None
    
    expiry_deadline = now + timedelta(days=expiry_days) if expiry_days else None
    search_value = search.lower().strip() if search else None
    
    # Compute status and apply filters
    certificate_rows = []
    for cert in certificates_list:
        computed_status = cert.compute_status(now)
        
        if status_filter and computed_status != status_filter:
            continue
        
        if expiry_deadline:
            if computed_status != CertificateStatusEnum.ACTIVE:
                continue
            not_after = cert.not_after
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            else:
                not_after = not_after.astimezone(timezone.utc)
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
    
    # Get issuer options for filter dropdown
    issuer_options = (
        db.query(CertificateAuthority)
        .order_by(CertificateAuthority.name.asc())
        .all()
    )
    
    # Calculate totals for summary cards
    total_certs = db.query(Certificate).count()
    total_cas = db.query(CertificateAuthority).count()
    total_profiles = db.query(Profile).count()
    
    # Calculate certificates expiring within 30 days and after 30 days
    thirty_days_from_now = now + timedelta(days=30)
    certs_expiring_within_30 = 0
    certs_expiring_after_30 = 0
    
    # Calculate certificate breakdown (active vs expired)
    active_certs = 0
    expired_certs = 0
    revoked_certs = 0
    
    # Calculate expiry breakdown for 7/30/90 days
    expiring_7_days = 0
    expiring_30_days = 0
    expiring_90_days = 0
    
    # Get upcoming expirations list (next 7-30 days)
    upcoming_expirations = []
    
    all_certificates = db.query(Certificate).all()
    for cert in all_certificates:
        not_after = cert.not_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        else:
            not_after = not_after.astimezone(timezone.utc)
        
        computed_status = cert.compute_status(now)
        
        # Count by status
        if computed_status == CertificateStatusEnum.ACTIVE:
            active_certs += 1
        elif computed_status == CertificateStatusEnum.EXPIRED:
            expired_certs += 1
        elif computed_status == CertificateStatusEnum.REVOKED:
            revoked_certs += 1
        
        # Count expiring certificates (only active ones)
        if computed_status == CertificateStatusEnum.ACTIVE:
            days_until_expiry = (not_after - now).days
            if 0 <= days_until_expiry <= 7:
                expiring_7_days += 1
            if 0 <= days_until_expiry <= 30:
                expiring_30_days += 1
            if 0 <= days_until_expiry <= 90:
                expiring_90_days += 1
            
            # Collect upcoming expirations (7-30 days)
            if 7 <= days_until_expiry <= 30:
                upcoming_expirations.append({
                    "certificate": cert,
                    "days_until_expiry": days_until_expiry,
                    "expiry_date": not_after,
                })
            
            if now <= not_after <= thirty_days_from_now:
                certs_expiring_within_30 += 1
            elif not_after > thirty_days_from_now:
                certs_expiring_after_30 += 1
    
    # Sort upcoming expirations by expiry date
    upcoming_expirations.sort(key=lambda x: x["expiry_date"])
    
    # Calculate percentages for chart (avoid division by zero)
    expiring_7_pct = (expiring_7_days / total_certs * 100) if total_certs > 0 else 0
    expiring_30_pct = (expiring_30_days / total_certs * 100) if total_certs > 0 else 0
    expiring_90_pct = (expiring_90_days / total_certs * 100) if total_certs > 0 else 0
    
    # Calculate CA health status
    active_cas = 0
    inactive_cas = 0
    for ca in authorities:
        if ca.status.value == "ACTIVE":
            active_cas += 1
        else:
            inactive_cas += 1
    
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "app_name": settings.APP_NAME,
            "profiles": profiles,
            "authorities": authorities,
            "certificates": certificate_rows,
            "status_options": list(CertificateStatusEnum),
            "issuer_options": issuer_options,
            "quick_expiry_options": (7, 30, 90),
            "filters": {
                "search": search or "",
                "issuer_ca_id": issuer_ca_id or "",
                "status": status_filter.value if status_filter else "",
                "expiry_filter": expiry_days or "",
            },
            "total_certs": total_certs,
            "total_cas": total_cas,
            "total_profiles": total_profiles,
            "certs_expiring_within_30": certs_expiring_within_30,
            "certs_expiring_after_30": certs_expiring_after_30,
            # Widget data
            "active_certs": active_certs,
            "expired_certs": expired_certs,
            "revoked_certs": revoked_certs,
            "expiring_7_days": expiring_7_days,
            "expiring_30_days": expiring_30_days,
            "expiring_90_days": expiring_90_days,
            "expiring_7_pct": round(expiring_7_pct),
            "expiring_30_pct": round(expiring_30_pct),
            "expiring_90_pct": round(expiring_90_pct),
            "upcoming_expirations": upcoming_expirations[:10],  # Limit to 10 most urgent
            "active_cas": active_cas,
            "inactive_cas": inactive_cas,
        },
    )
