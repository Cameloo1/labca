"""Unauthenticated public PKI routes: CA certificates, chains, CRLs, and the trust bundle."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db
from app.logging_config import logger
from app.models import CertificateAuthority
from app.services import crl_service, pki_service
from app.services.pki_service import DER_CERT_CONTENT_TYPE, DER_CRL_CONTENT_TYPE, PEM_CONTENT_TYPE

router = APIRouter(prefix="/pki", tags=["pki"])

OK_CACHE_CONTROL = "public, max-age=60"
ERROR_CACHE_CONTROL = "no-store"
MAX_STATIC_BYTES = 1024 * 1024
MAX_CA_ID_LENGTH = 36
ROOT_CA_FILE = "root-ca.pem"
ROOT_CRL_FILE = "root-crl.der"


def _not_found() -> Response:
    return PlainTextResponse("Not found\n", status_code=404, headers={"Cache-Control": ERROR_CACHE_CONTROL})


def _crl_unavailable() -> Response:
    return PlainTextResponse(
        "CRL temporarily unavailable\n", status_code=503, headers={"Cache-Control": ERROR_CACHE_CONTROL}
    )


def _ok(body: bytes, content_type: str) -> Response:
    return Response(content=body, media_type=content_type, headers={"Cache-Control": OK_CACHE_CONTROL})


def _pem(certs: list[x509.Certificate]) -> bytes:
    return b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs)


def _rfc3339(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _static_file(name: str) -> Optional[Path]:
    directory = get_settings().PKI_STATIC_DIR
    if not directory:
        return None
    path = Path(directory) / name
    try:
        return path if path.is_file() else None
    except OSError:
        return None


def _read_static(name: str) -> Optional[bytes]:
    path = _static_file(name)
    if path is None:
        return None
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_STATIC_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_STATIC_BYTES:
        logger.warning("Static PKI file is too large to serve", extra={"file_name": name})
        return None
    return data


# --- shared handlers -------------------------------------------------------


def _ca_pem(ca: CertificateAuthority) -> Response:
    return _ok(ca.cert_pem.encode("utf-8"), PEM_CONTENT_TYPE)


def _ca_der(ca: CertificateAuthority) -> Response:
    try:
        cert = pki_service.load_ca_certificate(ca)
    except ValueError:
        return _not_found()
    return _ok(cert.public_bytes(serialization.Encoding.DER), DER_CERT_CONTENT_TYPE)


def _chain_pem(ca: CertificateAuthority, db: Session) -> Response:
    try:
        certs = pki_service.chain_certificates(ca, db)
    except ValueError:
        return _not_found()
    return _ok(_pem(certs), PEM_CONTENT_TYPE)


def _crl(ca: CertificateAuthority, db: Session, *, pem: bool) -> Response:
    try:
        record = crl_service.get_current_crl(db, ca)
    except crl_service.CrlUnavailableError:
        return _crl_unavailable()
    if pem:
        body = x509.load_der_x509_crl(record.der).public_bytes(serialization.Encoding.PEM)
        return _ok(body, PEM_CONTENT_TYPE)
    return _ok(record.der, DER_CRL_CONTENT_TYPE)


# --- index and trust bundle ------------------------------------------------


@router.get("/index.json")
def index_json(db: Session = Depends(get_db)) -> Response:
    settings = get_settings()
    issuer = pki_service.resolve_workload_issuer(db, settings)
    root: Optional[dict[str, str]] = None
    if _static_file(ROOT_CA_FILE) is not None:
        root = {
            "ca_pem_url": pki_service.public_url("/pki/root/ca.pem", settings),
            "crl_der_url": pki_service.public_url("/pki/root/crl.der", settings),
        }
    rows = db.scalars(select(CertificateAuthority).order_by(CertificateAuthority.name, CertificateAuthority.id)).all()
    cas: list[dict[str, Any]] = []
    for row in rows:
        if not pki_service.ca_has_key(row):
            continue
        try:
            cert = pki_service.load_ca_certificate(row)
        except ValueError:
            logger.warning("CA certificate does not parse", extra={"ca_id": row.id})
            continue
        cas.append(
            {
                "id": row.id,
                "name": row.name,
                "subject": cert.subject.rfc4514_string(),
                "sha256_fingerprint": pki_service.sha256_fingerprint_hex(cert),
                "not_before": _rfc3339(cert.not_valid_before_utc),
                "not_after": _rfc3339(cert.not_valid_after_utc),
                "status": row.status.value,
                "urls": pki_service.ca_urls(row.id, settings),
            }
        )
    body = {
        "generated_at": _rfc3339(datetime.now(timezone.utc)),
        "trust_bundle_url": pki_service.public_url("/pki/trust-bundle.pem", settings),
        "workload_issuer_ca_id": issuer.id if issuer is not None else None,
        "root": root,
        "cas": cas,
    }
    return JSONResponse(body, headers={"Cache-Control": OK_CACHE_CONTROL})


@router.get("/trust-bundle.pem")
def trust_bundle(db: Session = Depends(get_db)) -> Response:
    certs = pki_service.trust_bundle_certificates(db)
    if not certs:
        return _not_found()
    return _ok(_pem(certs), PEM_CONTENT_TYPE)


# --- workload issuer -------------------------------------------------------


@router.get("/issuing/ca.pem")
def issuing_ca_pem(db: Session = Depends(get_db)) -> Response:
    ca = pki_service.resolve_workload_issuer(db)
    return _not_found() if ca is None else _ca_pem(ca)


@router.get("/issuing/ca.der")
def issuing_ca_der(db: Session = Depends(get_db)) -> Response:
    ca = pki_service.resolve_workload_issuer(db)
    return _not_found() if ca is None else _ca_der(ca)


@router.get("/issuing/chain.pem")
def issuing_chain_pem(db: Session = Depends(get_db)) -> Response:
    ca = pki_service.resolve_workload_issuer(db)
    return _not_found() if ca is None else _chain_pem(ca, db)


@router.get("/issuing/crl.der")
def issuing_crl_der(db: Session = Depends(get_db)) -> Response:
    ca = pki_service.resolve_workload_issuer(db)
    return _not_found() if ca is None else _crl(ca, db, pem=False)


@router.get("/issuing/crl.pem")
def issuing_crl_pem(db: Session = Depends(get_db)) -> Response:
    ca = pki_service.resolve_workload_issuer(db)
    return _not_found() if ca is None else _crl(ca, db, pem=True)


# --- per-CA routes ---------------------------------------------------------


def _keyed_ca(db: Session, ca_id: str) -> Optional[CertificateAuthority]:
    if len(ca_id) > MAX_CA_ID_LENGTH:
        return None
    return pki_service.get_keyed_ca(db, ca_id)


@router.get("/cas/{ca_id}/ca.pem")
def ca_pem(ca_id: str, db: Session = Depends(get_db)) -> Response:
    ca = _keyed_ca(db, ca_id)
    return _not_found() if ca is None else _ca_pem(ca)


@router.get("/cas/{ca_id}/ca.der")
def ca_der(ca_id: str, db: Session = Depends(get_db)) -> Response:
    ca = _keyed_ca(db, ca_id)
    return _not_found() if ca is None else _ca_der(ca)


@router.get("/cas/{ca_id}/chain.pem")
def ca_chain_pem(ca_id: str, db: Session = Depends(get_db)) -> Response:
    ca = _keyed_ca(db, ca_id)
    return _not_found() if ca is None else _chain_pem(ca, db)


@router.get("/cas/{ca_id}/crl.der")
def ca_crl_der(ca_id: str, db: Session = Depends(get_db)) -> Response:
    ca = _keyed_ca(db, ca_id)
    return _not_found() if ca is None else _crl(ca, db, pem=False)


@router.get("/cas/{ca_id}/crl.pem")
def ca_crl_pem(ca_id: str, db: Session = Depends(get_db)) -> Response:
    ca = _keyed_ca(db, ca_id)
    return _not_found() if ca is None else _crl(ca, db, pem=True)


# --- offline root files ----------------------------------------------------


@router.get("/root/ca.pem")
def root_ca_pem() -> Response:
    data = _read_static(ROOT_CA_FILE)
    return _not_found() if data is None else _ok(data, PEM_CONTENT_TYPE)


@router.get("/root/crl.der")
def root_crl_der() -> Response:
    data = _read_static(ROOT_CRL_FILE)
    return _not_found() if data is None else _ok(data, DER_CRL_CONTENT_TYPE)
