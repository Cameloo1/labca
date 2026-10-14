"""Certificate issuance routines that sign requests with an existing CA."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Dict, List, Optional, Type, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from sqlalchemy.orm import Session

from app.models import CertificateAuthority, CertificateStatusEnum, CertificateTypeEnum
from app.schemas import IssueFromCAConfig
from app.services.persistence import create_certificate

HASH_ALGOS: Dict[str, Type[Union[hashes.SHA256, hashes.SHA384, hashes.SHA512]]] = {
    "SHA256": hashes.SHA256,
    "SHA384": hashes.SHA384,
    "SHA512": hashes.SHA512,
}

CURVE_MAP: Dict[str, Type[Union[ec.SECP256R1, ec.SECP384R1, ec.SECP521R1]]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}


def issue_cert_from_ca(
    config: IssueFromCAConfig,
    ca: CertificateAuthority,
    db: Session,
):
    ca_certificate = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
    ca_key = _load_ca_private_key(ca)

    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=1)
    not_after = not_before + timedelta(days=config.validity_days)
    issuer_expiry = _as_aware(ca.not_after) if ca.not_after else None
    if issuer_expiry and not_after > issuer_expiry:
        raise ValueError("Requested validity exceeds issuer CA validity.")

    subject = _build_subject(
        cn=config.common_name,
        o=config.organization,
        ou=config.organizational_unit,
        c=config.country,
        st=config.state,
        l=config.locality,
    )

    key = _generate_private_key(config)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    san_entries: List[x509.GeneralName] = []
    for dns in config.dns_sans:
        san_entries.append(x509.DNSName(dns))
    for ip in config.ip_sans:
        san_entries.append(x509.IPAddress(ip_address(ip)))
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=config.is_ca, path_length=0 if config.is_ca else None),
        critical=True,
    )
    key_usage = _build_key_usage(config.is_ca)
    builder = builder.add_extension(key_usage, critical=True)
    eku = _build_extended_key_usage(config)
    if eku:
        builder = builder.add_extension(eku, critical=False)

    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    builder = builder.add_extension(ski, critical=False)
    try:
        aki = ca_certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    builder = builder.add_extension(aki, critical=False)

    hash_algo = HASH_ALGOS[config.hash_algorithm]()
    certificate = builder.sign(private_key=ca_key, algorithm=hash_algo)

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    stored_key = _encrypt_private_key(key_pem.encode("utf-8")) if config.store_in_db else None

    certificate_record = create_certificate(
        db,
        {
            "ca_id": ca.id,
            "type": CertificateTypeEnum.INTERMEDIATE if config.is_ca else CertificateTypeEnum.LEAF,
            "common_name": config.common_name,
            "san_dns": config.dns_sans,
            "san_ips": config.ip_sans,
            "serial_number": f"{certificate.serial_number:x}",
            "not_before": certificate.not_valid_before_utc,
            "not_after": certificate.not_valid_after_utc,
            "key_algorithm": "RSA" if isinstance(key, rsa.RSAPrivateKey) else "ECDSA",
            "key_size": key.key_size,
            "status": CertificateStatusEnum.ACTIVE,
            "environment_tags": config.environment_tags,
            "owner": config.owner,
            "stored_key_encrypted_pem": stored_key,
            "cert_pem": cert_pem,
            "is_ephemeral": not config.store_in_db,
        },
        ca=ca,
    )

    certificate_record._issued_key_pem = key_pem  # type: ignore[attr-defined]
    return certificate_record


def _load_ca_private_key(ca: CertificateAuthority):
    if not ca.key_encrypted_pem:
        raise ValueError("CA private key is not available for issuance.")
    raw = _decrypt_private_key(ca.key_encrypted_pem)
    return serialization.load_pem_private_key(raw, password=None)


def _generate_private_key(config: IssueFromCAConfig):
    if config.key_algorithm == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=config.key_size or 2048)
    curve_cls = CURVE_MAP[config.curve or "P-256"]
    return ec.generate_private_key(curve_cls())


def _build_subject(
    *,
    cn: str,
    o: Optional[str],
    ou: Optional[str],
    c: Optional[str],
    st: Optional[str],
    l: Optional[str],
) -> x509.Name:
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if o:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    if ou:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou))
    if l:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, l))
    if st:
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, st))
    if c:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    return x509.Name(attributes)


def _build_key_usage(is_ca: bool) -> x509.KeyUsage:
    if is_ca:
        return x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _build_extended_key_usage(config: IssueFromCAConfig) -> Optional[x509.ExtendedKeyUsage]:
    if config.is_ca:
        return None
    oids: List[ObjectIdentifier] = []
    if config.usage_preset == "server_tls":
        oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if config.usage_preset == "client_tls":
        oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    return x509.ExtendedKeyUsage(oids) if oids else None


def _encrypt_private_key(key_bytes: bytes) -> str:
    return "enc::" + base64.b64encode(key_bytes).decode("utf-8")


def _decrypt_private_key(encoded: str) -> bytes:
    if encoded.startswith("enc::"):
        encoded = encoded[len("enc::") :]
    return base64.b64decode(encoded.encode("utf-8"))


def _as_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
