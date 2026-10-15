"""Functions for creating or importing certificate authorities within LabCA."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Type, Union, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from app.models import CASourceTypeEnum, CAStatusEnum, CertificateAuthority
from app.schemas import ImportCAConfig, RootCAConfig
from app.services import keystore
from app.services.persistence import create_certificate_authority

HASH_ALGORITHMS: Dict[str, Type[Union[hashes.SHA256, hashes.SHA384, hashes.SHA512]]] = {
    "SHA256": hashes.SHA256,
    "SHA384": hashes.SHA384,
    "SHA512": hashes.SHA512,
}

CURVE_MAP: Dict[str, Type[Union[ec.SECP256R1, ec.SECP384R1, ec.SECP521R1]]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}


def create_root_ca(config: RootCAConfig, db: Session) -> CertificateAuthority:
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=5)
    not_after = not_before + timedelta(days=365 * config.validity_years)

    private_key = _generate_private_key(config)
    subject = _build_subject(
        cn=config.subject_cn,
        o=config.subject_o,
        ou=config.subject_ou,
        c=config.subject_c,
        st=config.subject_st,
        l=config.subject_l,
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=config.path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(ski, critical=False).add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        ),
        critical=False,
    )

    hash_algo = HASH_ALGORITHMS[config.hash_algorithm]()
    certificate = builder.sign(private_key=private_key, algorithm=hash_algo)

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ca_id = str(uuid.uuid4())
    encrypted_key = keystore.seal_ca_key(ca_id, key_bytes)

    ca_record = create_certificate_authority(
        db,
        {
            "id": ca_id,
            "name": config.name,
            "source_type": CASourceTypeEnum.ROOT,
            "parent_ca_id": None,
            "subject_cn": config.subject_cn,
            "subject_json": _subject_json_from_config(config),
            "serial_number": f"{certificate.serial_number:x}",
            "not_before": certificate.not_valid_before_utc,
            "not_after": certificate.not_valid_after_utc,
            "key_algorithm": _key_algorithm_label(private_key),
            "key_size": private_key.key_size,
            "status": CAStatusEnum.ACTIVE,
            "cert_pem": cert_pem,
            "key_encrypted_pem": encrypted_key,
        },
    )

    _remember_master_passphrase(config.master_passphrase)
    return ca_record


def import_ca(config: ImportCAConfig, db: Session) -> CertificateAuthority:
    certificate = x509.load_pem_x509_certificate(config.cert_pem.encode("utf-8"))
    password = config.key_passphrase.encode("utf-8") if config.key_passphrase else None
    private_key = serialization.load_pem_private_key(config.key_pem.encode("utf-8"), password=password)

    try:
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = basic_constraints.ca
        path_length = basic_constraints.path_length
    except x509.ExtensionNotFound:
        is_ca = False
        path_length = None

    source_type = CASourceTypeEnum.EXTERNAL_IMPORTED
    if config.allow_intermediate_issuance and is_ca:
        source_type = CASourceTypeEnum.INTERMEDIATE

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ca_id = str(uuid.uuid4())
    encrypted_key = keystore.seal_ca_key(ca_id, key_bytes)

    ca_record = create_certificate_authority(
        db,
        {
            "id": ca_id,
            "name": config.name,
            "source_type": source_type,
            "parent_ca_id": None,
            "subject_cn": _get_subject_attribute(certificate, NameOID.COMMON_NAME) or "",
            "subject_json": _subject_json_from_cert(certificate, path_length),
            "serial_number": f"{certificate.serial_number:x}",
            "not_before": certificate.not_valid_before_utc,
            "not_after": certificate.not_valid_after_utc,
            "key_algorithm": _key_algorithm_label(private_key),
            "key_size": cast(Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey], private_key).key_size,
            "status": CAStatusEnum.ACTIVE,
            "cert_pem": cert_pem,
            "key_encrypted_pem": encrypted_key,
        },
    )

    _remember_master_passphrase(config.master_passphrase)
    return ca_record


def _generate_private_key(config: RootCAConfig):
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


def _subject_json_from_config(config: RootCAConfig) -> Dict[str, Optional[str]]:
    return {
        "CN": config.subject_cn,
        "O": config.subject_o,
        "OU": config.subject_ou,
        "C": config.subject_c,
        "ST": config.subject_st,
        "L": config.subject_l,
    }


def _subject_json_from_cert(certificate: x509.Certificate, path_length: Optional[int]) -> Dict[str, Any]:
    attrs: Dict[str, Any] = {
        "CN": None,
        "O": None,
        "OU": None,
        "C": None,
        "ST": None,
        "L": None,
        "path_length": path_length,
    }
    for component, oid in [
        ("CN", NameOID.COMMON_NAME),
        ("O", NameOID.ORGANIZATION_NAME),
        ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("C", NameOID.COUNTRY_NAME),
        ("ST", NameOID.STATE_OR_PROVINCE_NAME),
        ("L", NameOID.LOCALITY_NAME),
    ]:
        values = certificate.subject.get_attributes_for_oid(oid)
        if values:
            attrs[component] = values[0].value
    return attrs


def _get_subject_attribute(certificate: x509.Certificate, oid: x509.ObjectIdentifier) -> Optional[str]:
    values = certificate.subject.get_attributes_for_oid(oid)
    return cast(str, values[0].value) if values else None


def _key_algorithm_label(private_key) -> str:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return "RSA"
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return "ECDSA"
    return private_key.__class__.__name__


def _remember_master_passphrase(passphrase: Optional[str]) -> None:
    if not passphrase:
        return
    # Placeholder for securely storing passphrases (to be implemented in future tasks).
    _ = hashes.Hash(hashes.SHA256())
    _.update(passphrase.encode("utf-8"))
    _digest = _.finalize()
    # In a real system we'd persist this hash; for now, we simply note it in-memory.
    _ = _digest  # pragma: no cover
