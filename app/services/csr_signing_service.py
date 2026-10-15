"""CSR parsing and leaf certificate signing for a caller-supplied public key.

LabCA never sees the private key for certificates issued through this module.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Optional, Sequence, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from sqlalchemy.orm import Session

from app.models import (
    CAStatusEnum,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
)
from app.services.cert_issuance_service import load_ca_private_key
from app.services.persistence import create_certificate
from app.services.uri_san import validate_uri_san

MAX_CSR_PEM_BYTES = 16384
ALLOWED_EC_CURVES: dict[str, int] = {"secp256r1": 256, "secp384r1": 384}
MIN_RSA_BITS, MAX_RSA_BITS = 2048, 8192
EKU_PRESETS: dict[str, list[ObjectIdentifier]] = {
    "server_tls": [ExtendedKeyUsageOID.SERVER_AUTH],
    "client_tls": [ExtendedKeyUsageOID.CLIENT_AUTH],
    "mtls": [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
}

_UNSUPPORTED_KEY_MESSAGE = "Unsupported key type. Use ECDSA P-256 or P-384, or RSA 2048 to 8192 bits."

PublicKey = Union[ec.EllipticCurvePublicKey, rsa.RSAPublicKey]


class CsrError(ValueError):
    """A CSR was rejected; the message is safe to return to clients."""


@dataclass(frozen=True)
class CsrInfo:
    public_key: PublicKey
    common_name: Optional[str]
    dns_sans: list[str]
    ip_sans: list[str]
    uri_sans: list[str]
    key_algorithm: str  # "ECDSA" | "RSA"
    key_size: int


def load_and_verify_csr(csr_pem: str) -> CsrInfo:
    if len(csr_pem.encode("utf-8")) > MAX_CSR_PEM_BYTES:
        raise CsrError("CSR is too large.")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        public_key = csr.public_key()
        valid = csr.is_signature_valid
    except Exception:  # any parser failure maps to one fixed client message
        raise CsrError("CSR could not be parsed.") from None
    if not valid:
        raise CsrError("CSR signature is invalid.")

    if not isinstance(public_key, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
        raise CsrError(_UNSUPPORTED_KEY_MESSAGE)
    key_algorithm, key_size = _classify_key(public_key)

    dns_sans: list[str] = []
    ip_sans: list[str] = []
    uri_sans: list[str] = []
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    except ValueError:
        raise CsrError("CSR could not be parsed.") from None
    if san is not None:
        for name in san:
            if isinstance(name, x509.DNSName):
                dns_sans.append(name.value)
            elif isinstance(name, x509.IPAddress):
                ip_sans.append(str(name.value))
            elif isinstance(name, x509.UniformResourceIdentifier):
                try:
                    uri_sans.append(validate_uri_san(name.value))
                except ValueError as exc:
                    raise CsrError(str(exc)) from None
            else:
                raise CsrError("Unsupported SAN type in CSR.")

    common_name: Optional[str] = None
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        value = cn_attrs[0].value
        common_name = value if isinstance(value, str) else value.decode("utf-8", errors="replace")

    return CsrInfo(
        public_key=public_key,
        common_name=common_name,
        dns_sans=dns_sans,
        ip_sans=ip_sans,
        uri_sans=uri_sans,
        key_algorithm=key_algorithm,
        key_size=key_size,
    )


def _classify_key(public_key: object) -> tuple[str, int]:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name in ALLOWED_EC_CURVES:
            return "ECDSA", public_key.key_size
    elif isinstance(public_key, rsa.RSAPublicKey):
        if MIN_RSA_BITS <= public_key.key_size <= MAX_RSA_BITS:
            return "RSA", public_key.key_size
    raise CsrError(_UNSUPPORTED_KEY_MESSAGE)


def issue_leaf_for_public_key(
    db: Session,
    ca: CertificateAuthority,
    public_key: PublicKey,
    *,
    common_name: str,
    dns_sans: Sequence[str],
    ip_sans: Sequence[str],
    uri_sans: Sequence[str],
    validity: timedelta,
    usage_preset: str,
    environment_tags: Sequence[str],
    owner: Optional[str] = None,
    issued_by_token_id: Optional[str] = None,
) -> Certificate:
    if ca.status != CAStatusEnum.ACTIVE:
        raise ValueError("Issuer CA is not active.")
    if usage_preset not in EKU_PRESETS:
        raise ValueError("Unknown usage preset.")
    if not 1 <= len(common_name) <= 64:
        raise ValueError("Common name must be 1 to 64 characters.")
    key_algorithm, key_size = _classify_key(public_key)

    ca_certificate = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
    ca_key = load_ca_private_key(ca)

    not_before = datetime.now(timezone.utc) - timedelta(minutes=1)
    not_after = not_before + validity
    if ca.not_after is not None and not_after > _as_aware(ca.not_after):
        raise ValueError("Requested validity exceeds issuer CA validity.")

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    san_entries: list[x509.GeneralName] = [x509.DNSName(value) for value in dns_sans]
    san_entries.extend(x509.IPAddress(ip_address(value)) for value in ip_sans)
    san_entries.extend(x509.UniformResourceIdentifier(value) for value in uri_sans)
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=key_algorithm == "RSA",
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(x509.ExtendedKeyUsage(EKU_PRESETS[usage_preset]), critical=False)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    try:
        ca_ski = ca_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski)
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    use_sha384 = isinstance(ca_key, ec.EllipticCurvePrivateKey) and ca_key.curve.name == "secp384r1"
    algorithm = hashes.SHA384() if use_sha384 else hashes.SHA256()
    certificate = builder.sign(private_key=ca_key, algorithm=algorithm)
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    return create_certificate(
        db,
        {
            "id": str(uuid.uuid4()),
            "ca_id": ca.id,
            "type": CertificateTypeEnum.LEAF,
            "common_name": common_name,
            "san_dns": list(dns_sans),
            "san_ips": list(ip_sans),
            "san_uris": list(uri_sans),
            "serial_number": format(certificate.serial_number, "x"),
            "not_before": certificate.not_valid_before_utc,
            "not_after": certificate.not_valid_after_utc,
            "key_algorithm": key_algorithm,
            "key_size": key_size,
            "status": CertificateStatusEnum.ACTIVE,
            "environment_tags": list(environment_tags),
            "owner": owner,
            "stored_key_encrypted_pem": None,
            "cert_pem": cert_pem,
            "is_ephemeral": False,
            "issued_by_token_id": issued_by_token_id,
        },
        ca=ca,
    )


def _as_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
