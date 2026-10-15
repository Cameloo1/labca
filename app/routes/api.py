from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional, Tuple, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_api_token, get_db
from app.logging_config import logger
from app.models import (
    ActorType,
    AllowKeyDownloadPolicy,
    ApiToken,
    AuditStatus,
    Certificate,
    CertificateAuthority,
    CertificateTypeEnum,
)
from app.schemas import (
    CertificateIssueRequest,
    CertificateMetadata,
    CertificateResponse,
    IssueFromCAConfig,
    SimpleCertConfig,
    TokenCreateRequest,
    TokenCreateResponse,
    TokenPermissions,
)
from app.services import keystore
from app.services.api_token_service import create_token
from app.services.audit_service import log_action
from app.services.cert_issuance_service import issue_cert_from_ca
from app.services.crypto_service import generate_self_signed_cert_simple
from app.services.quick_cert_service import save_quick_cert_to_db
from app.services.settings_service import get_app_settings

# Alias for the key_size type of the config models, which validate the value at runtime.
KeySize = Optional[Literal[2048, 3072, 4096]]

router = APIRouter(prefix="/api/v1", tags=["api"])


@router.post(
    "/tokens",
    response_model=TokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_api_token(
    payload: TokenCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin_secret: Optional[str] = Header(default=None, alias="X-LabCA-Admin-Secret"),
) -> TokenCreateResponse:
    settings = get_settings()
    configured_secret = settings.API_TOKEN_CREATION_SECRET
    if not configured_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API token creation is disabled. Set API_TOKEN_CREATION_SECRET to enable it.",
        )
    if admin_secret != configured_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin secret for token creation.",
        )

    token, raw_value = create_token(payload.name, payload.permissions.model_dump(), payload.expires_at, db)
    log_action(
        db,
        actor_type=ActorType.USER,
        actor_id="api-admin",
        action="CREATE_TOKEN",
        target_type="API_TOKEN",
        target_id=token.id,
        status=AuditStatus.SUCCESS,
        ip_address=_client_ip(request),
        details={
            "token_name": token.name,
            "token_prefix": token.token_prefix,
        },
    )
    logger.info(
        "API token created",
        extra={"token_prefix": token.token_prefix, "token_name": token.name},
    )
    permissions = TokenPermissions(**(token.permissions_json or {}))
    return TokenCreateResponse(
        id=token.id,
        name=token.name,
        token_prefix=token.token_prefix,
        token=raw_value,
        permissions=permissions,
        expires_at=token.expires_at,
        created_at=token.created_at,
    )


@router.post(
    "/certificates",
    response_model=CertificateResponse,
    status_code=status.HTTP_201_CREATED,
)
def issue_certificate_via_api(
    payload: CertificateIssueRequest,
    request: Request,
    db: Session = Depends(get_db),
    api_token: ApiToken = Depends(get_api_token),
) -> CertificateResponse:
    if not api_token.has_permission("issue"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API token is not permitted to issue certificates.",
        )
    if payload.issuer_ca_id:
        result, certificate = _issue_via_ca(payload, db)
    else:
        result, certificate = _issue_self_signed(payload, db)

    log_action(
        db,
        actor_type=ActorType.API_TOKEN,
        actor_id=api_token.token_prefix,
        action="ISSUE_CERT",
        target_type="CERTIFICATE",
        target_id=certificate.id,
        status=AuditStatus.SUCCESS,
        ip_address=_client_ip(request),
        details={
            "issuer_ca_id": certificate.ca_id,
            "common_name": certificate.common_name,
        },
    )
    logger.info(
        "Certificate issued via API",
        extra={"token_prefix": api_token.token_prefix, "certificate_id": certificate.id},
    )
    return result


@router.get(
    "/certificates/{certificate_id}",
    response_model=CertificateResponse,
)
def get_certificate_via_api(
    certificate_id: str,
    include_private_key: bool = Query(default=False),
    db: Session = Depends(get_db),
    api_token: ApiToken = Depends(get_api_token),
) -> CertificateResponse:
    if not api_token.has_permission("read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API token is not permitted to read certificates.",
        )
    certificate = db.get(Certificate, certificate_id)
    if certificate is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found.")
    settings = get_app_settings(db)
    key_allowed = _is_key_download_allowed(certificate, settings.allow_key_download_policy)
    private_key_pem: Optional[str] = None
    if include_private_key:
        if not key_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Key downloads are disabled for this certificate.",
            )
        if not certificate.stored_key_encrypted_pem:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Private key is not stored for this certificate.",
            )
        try:
            private_key_pem = keystore.unseal_cert_key(certificate.id, certificate.stored_key_encrypted_pem).decode(
                "utf-8"
            )
        except keystore.KeystoreError as exc:
            logger.error(
                "Stored key unseal failed",
                extra={"certificate_id": certificate.id, "error": type(exc).__name__},
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Stored private key could not be decrypted.",
            ) from None
    metadata = _build_metadata(certificate, key_allowed)
    return CertificateResponse(
        certificate_id=certificate.id,
        certificate_pem=certificate.cert_pem,
        private_key_pem=private_key_pem,
        metadata=metadata,
    )


def _issue_via_ca(payload: CertificateIssueRequest, db: Session) -> Tuple[CertificateResponse, Certificate]:
    ca = db.get(CertificateAuthority, payload.issuer_ca_id)
    if ca is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Issuer CA not found.")
    config = IssueFromCAConfig(
        issuer_ca_id=ca.id,
        common_name=payload.common_name,
        dns_sans=payload.dns_sans,
        ip_sans=payload.ip_sans,
        organization=payload.organization,
        organizational_unit=payload.organizational_unit,
        country=payload.country,
        state=payload.state,
        locality=payload.locality,
        key_algorithm=payload.key_algorithm,
        key_size=cast(KeySize, payload.key_size) if payload.key_algorithm == "RSA" else None,
        curve=payload.curve if payload.key_algorithm == "ECDSA" else None,
        hash_algorithm=payload.hash_algorithm,
        validity_days=payload.validity_days,
        usage_preset=payload.usage_preset,
        is_ca=payload.is_ca,
        store_in_db=payload.store_in_db,
        environment_tags=payload.environment_tags,
        owner=payload.owner,
        enable_expiration_reminders=payload.enable_expiration_reminders,
    )
    certificate = issue_cert_from_ca(config, ca, db)
    issued_key = getattr(certificate, "_issued_key_pem", None)
    settings = get_app_settings(db)
    key_allowed = _is_key_download_allowed(certificate, settings.allow_key_download_policy)
    include_private_key = bool(payload.return_private_key and issued_key and key_allowed)
    metadata = _build_metadata(certificate, key_allowed)
    response = CertificateResponse(
        certificate_id=certificate.id,
        certificate_pem=certificate.cert_pem,
        private_key_pem=issued_key if include_private_key else None,
        metadata=metadata,
    )
    return response, certificate


def _issue_self_signed(payload: CertificateIssueRequest, db: Session) -> Tuple[CertificateResponse, Certificate]:
    simple_config = SimpleCertConfig(
        common_name=payload.common_name,
        dns_sans=payload.dns_sans,
        ip_sans=payload.ip_sans,
        organization=payload.organization,
        organizational_unit=payload.organizational_unit,
        country=payload.country,
        state=payload.state,
        locality=payload.locality,
        key_algorithm=payload.key_algorithm,
        key_size=cast(KeySize, payload.key_size) if payload.key_algorithm == "RSA" else None,
        curve=payload.curve if payload.key_algorithm == "ECDSA" else None,
        hash_algorithm=payload.hash_algorithm,
        validity_days=payload.validity_days,
        usage_preset=payload.usage_preset,
        output_pem_cert=True,
        output_pem_key=True,
        output_combined_pem=False,
        output_pfx=False,
        label=payload.owner,
        pfx_password=None,
    )
    bundle = generate_self_signed_cert_simple(simple_config)
    certificate = save_quick_cert_to_db(
        bundle,
        simple_config,
        db,
        store_in_labca=payload.store_in_db,
        environment_tags=payload.environment_tags,
        owner=payload.owner,
    )
    private_key = bundle.key_pem.decode("utf-8") if bundle.key_pem else None
    settings = get_app_settings(db)
    key_allowed = _is_key_download_allowed(certificate, settings.allow_key_download_policy)
    include_private_key = bool(payload.return_private_key and private_key and key_allowed)
    metadata = _build_metadata(certificate, key_allowed)
    response = CertificateResponse(
        certificate_id=certificate.id,
        certificate_pem=certificate.cert_pem,
        private_key_pem=private_key if include_private_key else None,
        metadata=metadata,
    )
    return response, certificate


def _build_metadata(certificate: Certificate, key_allowed: bool) -> CertificateMetadata:
    status = certificate.compute_status()
    return CertificateMetadata(
        id=certificate.id,
        issuer_ca_id=certificate.ca_id,
        type=certificate.type.value,
        common_name=certificate.common_name,
        serial_number=certificate.serial_number,
        not_before=_ensure_timezone(certificate.not_before),
        not_after=_ensure_timezone(certificate.not_after),
        owner=certificate.owner,
        environment_tags=certificate.environment_tags or [],
        status=status.value,
        download_allowed=key_allowed,
    )


def _ensure_timezone(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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


def _client_ip(request: Request) -> Optional[str]:
    if request.client:
        return request.client.host
    return None
