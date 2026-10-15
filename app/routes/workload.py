"""Workload attestation routes: short-lived certificates for Kubernetes ServiceAccounts.

Callers prove their identity with a projected ServiceAccount token that LabCA
checks through the Kubernetes TokenReview API. Errors use the body shape
{"error": <code>, "detail": <text>} and never echo a token.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db
from app.logging_config import logger
from app.models import ActorType, AuditStatus, Certificate
from app.services import crl_service, keystore, pki_service, revocation_service
from app.services.audit_service import log_action
from app.services.csr_signing_service import CsrError, issue_leaf_for_public_key, load_and_verify_csr
from app.services.tokenreview import (
    NotAServiceAccount,
    ReviewedIdentity,
    TokenRejected,
    TokenReviewer,
    TokenReviewUnavailable,
    get_token_reviewer,
)
from app.services.workload_service import (
    derived_dns_sans,
    get_rate_limiter,
    parse_allowlist,
    spiffe_id_for,
    workload_trust_bundle,
)

router = APIRouter(prefix="/api/v1/workload", tags=["workload"])

MAX_BODY_BYTES = 32 * 1024
MAX_TOKEN_BYTES = 16384
REVOKE_REASONS = ("keyCompromise", "superseded", "cessationOfOperation", "unspecified")
_SERIAL_RE = re.compile(r"^[0-9a-fA-F]{1,40}$")


class _Call:
    """One request: builds the response and writes the audit row and log line for it."""

    def __init__(self, request: Request, db: Session, action: str) -> None:
        self.request = request
        self.db = db
        self.action = action
        self.spiffe_id: Optional[str] = None
        self.identity: Optional[ReviewedIdentity] = None

    def _record(
        self,
        *,
        result: str,
        reason: Optional[str],
        http_status: int,
        target_id: Optional[str] = None,
        serial_hex: Optional[str] = None,
    ) -> None:
        ok = http_status < 400
        details: dict[str, Any] = {"result": result, "spiffe_id": self.spiffe_id, "reason": reason}
        if serial_hex is not None:
            details["serial_hex"] = serial_hex
        log_action(
            self.db,
            actor_type=ActorType.WORKLOAD,
            actor_id=self.spiffe_id[:255] if self.spiffe_id else None,
            action=self.action,
            target_type="certificate",
            target_id=target_id,
            status=AuditStatus.SUCCESS if ok else AuditStatus.FAILURE,
            ip_address=self.request.client.host if self.request.client else None,
            details=details,
        )
        logger.info(
            "workload request action=%s result=%s status=%s spiffe_id=%s serial_hex=%s reason=%s",
            self.action,
            result,
            http_status,
            self.spiffe_id,
            serial_hex,
            reason,
        )

    def fail(
        self,
        http_status: int,
        code: str,
        detail: str,
        *,
        serial_hex: Optional[str] = None,
        target_id: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> JSONResponse:
        self._record(result=code, reason=detail, http_status=http_status, target_id=target_id, serial_hex=serial_hex)
        body: dict[str, Any] = {"error": code, "detail": detail}
        if extra:
            body.update(extra)
        return JSONResponse(body, status_code=http_status, headers={"Cache-Control": "no-store", **(headers or {})})

    def ok(
        self,
        http_status: int,
        result: str,
        body: dict[str, Any],
        *,
        target_id: Optional[str],
        serial_hex: Optional[str],
    ) -> JSONResponse:
        self._record(result=result, reason=None, http_status=http_status, target_id=target_id, serial_hex=serial_hex)
        return JSONResponse(body, status_code=http_status, headers={"Cache-Control": "no-store"})

    async def authenticate(self, reviewer: TokenReviewer) -> Optional[JSONResponse]:
        """Return an error response, or None after setting self.spiffe_id."""
        settings = get_settings()
        trust_domain = settings.WORKLOAD_TRUST_DOMAIN
        if not settings.WORKLOAD_ISSUANCE_ENABLED or not trust_domain:
            return self.fail(503, "issuer_unavailable", "Workload issuance is not enabled.")

        token = _bearer_token(self.request.headers.get("Authorization"))
        if token is None:
            return self.fail(401, "unauthenticated", "Missing or malformed bearer token.")

        try:
            identity: ReviewedIdentity = await run_in_threadpool(
                reviewer.review, token, settings.WORKLOAD_TOKEN_AUDIENCE
            )
        except TokenRejected:
            return self.fail(401, "unauthenticated", "Token was not accepted.")
        except NotAServiceAccount:
            return self.fail(403, "not_allowlisted", "Caller is not a Kubernetes service account.")
        except TokenReviewUnavailable:
            return self.fail(503, "issuer_unavailable", "Token review is unavailable.")

        if (identity.namespace, identity.service_account) not in parse_allowlist(settings.WORKLOAD_ALLOWLIST):
            return self.fail(403, "not_allowlisted", "Workload is not on the allowlist.")
        self.spiffe_id = spiffe_id_for(trust_domain, identity.namespace, identity.service_account)
        self.identity = identity
        return None


def _bearer_token(header: Optional[str]) -> Optional[str]:
    if not header:
        return None
    scheme, _, rest = header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = rest.strip()
    if not token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        return None
    return token


async def _read_body(request: Request) -> Optional[bytes]:
    """Return the body, or None when it is larger than MAX_BODY_BYTES."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _json_object(body: bytes) -> Optional[dict[str, Any]]:
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _rfc3339(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@router.post("/sign")
async def workload_sign(
    request: Request,
    db: Session = Depends(get_db),
    reviewer: TokenReviewer = Depends(get_token_reviewer),
) -> JSONResponse:
    call = _Call(request, db, "WORKLOAD_SIGN")
    failure = await call.authenticate(reviewer)
    if failure is not None:
        return failure
    spiffe_id = call.spiffe_id or ""
    settings = get_settings()

    issuer = pki_service.resolve_workload_issuer(db, settings)
    if issuer is None:
        return call.fail(503, "issuer_unavailable", "Workload issuer CA is not available.")

    retry_after = get_rate_limiter().acquire(spiffe_id)
    if retry_after is not None:
        return call.fail(
            429,
            "rate_limited",
            "Too many sign requests for this identity.",
            extra={"retry_after_s": retry_after},
            headers={"Retry-After": str(retry_after)},
        )

    raw = await _read_body(request)
    if raw is None:
        return call.fail(400, "invalid_csr", "Request body is too large.")
    payload = _json_object(raw)
    csr_pem = payload.get("csr_pem") if payload is not None else None
    if not isinstance(csr_pem, str):
        return call.fail(400, "invalid_csr", "Request body must be a JSON object with csr_pem.")
    try:
        csr = load_and_verify_csr(csr_pem)
    except CsrError as exc:
        return call.fail(400, "invalid_csr", str(exc))

    bundle = workload_trust_bundle(db, issuer)
    if not bundle:
        return call.fail(503, "issuer_unavailable", "No trust anchor is configured for the workload issuer.")

    identity = call.identity
    if identity is None:  # unreachable: authenticate() sets it whenever it returns None
        return call.fail(401, "unauthenticated", "Missing or malformed bearer token.")
    try:
        certificate = issue_leaf_for_public_key(
            db,
            issuer,
            csr.public_key,
            common_name=identity.service_account[:64],
            dns_sans=derived_dns_sans(identity.namespace, identity.service_account),
            ip_sans=[],
            uri_sans=[spiffe_id],
            validity=timedelta(minutes=settings.WORKLOAD_CERT_TTL_MINUTES),
            usage_preset="mtls",
            environment_tags=["workload"],
            owner=spiffe_id[:255],
            issued_to_spiffe_id=spiffe_id,
        )
    except (ValueError, keystore.KeystoreError) as exc:
        logger.error("Workload issuer cannot sign", extra={"error": type(exc).__name__, "reason": str(exc)})
        return call.fail(503, "issuer_unavailable", "Workload issuer CA cannot sign right now.")

    chain = pki_service.chain_certificates(issuer, db)
    chain_pem = certificate.cert_pem.rstrip("\n") + "\n" + "".join(_pem(item) for item in chain)
    body = {
        "spiffe_id": spiffe_id,
        "serial_hex": certificate.serial_number,
        "not_before": _rfc3339(certificate.not_before),
        "not_after": _rfc3339(certificate.not_after),
        "certificate_pem": certificate.cert_pem,
        "chain_pem": chain_pem,
        "trust_bundle_pem": "".join(_pem(item) for item in bundle),
    }
    return call.ok(201, "issued", body, target_id=certificate.id, serial_hex=certificate.serial_number)


@router.post("/revoke")
async def workload_revoke(
    request: Request,
    db: Session = Depends(get_db),
    reviewer: TokenReviewer = Depends(get_token_reviewer),
) -> JSONResponse:
    call = _Call(request, db, "WORKLOAD_REVOKE")
    failure = await call.authenticate(reviewer)
    if failure is not None:
        return failure
    spiffe_id = call.spiffe_id or ""

    raw = await _read_body(request)
    if raw is None:
        return call.fail(400, "invalid_request", "Request body is too large.")
    payload = _json_object(raw)
    if payload is None:
        return call.fail(400, "invalid_request", "Request body must be a JSON object.")
    serial_value = payload.get("serial_hex")
    reason = payload.get("reason")
    if not isinstance(serial_value, str) or not _SERIAL_RE.match(serial_value):
        return call.fail(400, "invalid_request", "serial_hex must be 1 to 40 hex digits.")
    if not isinstance(reason, str) or reason not in REVOKE_REASONS:
        return call.fail(400, "invalid_request", "reason must be one of " + ", ".join(REVOKE_REASONS) + ".")
    serial_hex = format(int(serial_value, 16), "x")

    certificate = db.scalars(select(Certificate).where(Certificate.serial_number == serial_hex)).first()
    if certificate is None or certificate.issued_to_spiffe_id is None:
        return call.fail(404, "not_found", "Certificate not found.", serial_hex=serial_hex)
    if certificate.issued_to_spiffe_id != spiffe_id:
        return call.fail(
            403,
            "not_owner",
            "Certificate belongs to another identity.",
            serial_hex=serial_hex,
            target_id=certificate.id,
        )

    already_revoked = certificate.revoked_at is not None
    if not already_revoked:
        revocation_service.revoke_certificate(certificate, reason, db, reason_code=reason)

    authority = certificate.ca
    try:
        if authority is None:
            raise crl_service.CrlUnavailableError("Certificate has no CA.")
        record = crl_service.get_current_crl(db, authority)
    except crl_service.CrlUnavailableError:
        return call.fail(
            503,
            "issuer_unavailable",
            "Revoked, but the CRL could not be regenerated.",
            serial_hex=serial_hex,
            target_id=certificate.id,
        )
    return call.ok(
        200,
        "already_revoked" if already_revoked else "revoked",
        {"revoked": True, "crl_number": record.crl_number},
        target_id=certificate.id,
        serial_hex=serial_hex,
    )
