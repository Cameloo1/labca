"""Cryptographic helpers for generating quick self-signed certificates within LabCA."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Dict, List, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
    ObjectIdentifier,
)

from app.schemas import AdvancedCertConfig, GeneratedCertBundle, SimpleCertConfig

CURVE_MAP: Dict[str, ec.EllipticCurve] = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}

HASH_ALGORITHM_MAP: Dict[str, Union[hashes.SHA256, hashes.SHA384, hashes.SHA512]] = {
    "SHA256": hashes.SHA256(),
    "SHA384": hashes.SHA384(),
    "SHA512": hashes.SHA512(),
}


def generate_self_signed_cert_simple(config: SimpleCertConfig) -> GeneratedCertBundle:
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=1)
    not_after = not_before + timedelta(days=config.validity_days)

    private_key = _generate_private_key(config)
    public_key = private_key.public_key()

    name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, config.common_name)]
    if config.organization:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.organization))
    if config.organizational_unit:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.organizational_unit))
    if config.country:
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, config.country))
    if config.state:
        name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.state))
    if config.locality:
        name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, config.locality))

    subject = x509.Name(name_attributes)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    san_entries: List[x509.GeneralName] = []
    for dns in config.dns_sans:
        san_entries.append(x509.DNSName(dns))
    for ip_str in config.ip_sans:
        san_entries.append(x509.IPAddress(ip_address(ip_str)))

    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    key_usage = x509.KeyUsage(
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
    builder = builder.add_extension(key_usage, critical=True)

    eku_oid = (
        ExtendedKeyUsageOID.SERVER_AUTH if config.usage_preset == "server_tls" else ExtendedKeyUsageOID.CLIENT_AUTH
    )
    builder = builder.add_extension(x509.ExtendedKeyUsage([eku_oid]), critical=False)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)

    hash_algo = HASH_ALGORITHM_MAP[config.hash_algorithm]
    certificate = builder.sign(private_key=private_key, algorithm=hash_algo)

    cert_pem = None
    key_pem = None
    combined_pem = None
    pfx_blob = None

    if config.output_pem_cert:
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

    if config.output_pem_key:
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    if config.output_combined_pem and cert_pem and key_pem:
        combined_pem = cert_pem + b"\n" + key_pem

    if config.output_pfx:
        if not config.pfx_password:
            raise ValueError("PFX password is required when output_pfx is enabled.")
        encryption = serialization.BestAvailableEncryption(config.pfx_password.encode("utf-8"))
        label = (config.label or config.common_name).encode("utf-8")
        pfx_blob = pkcs12.serialize_key_and_certificates(
            name=label,
            key=private_key,
            cert=certificate,
            cas=None,
            encryption_algorithm=encryption,
        )

    key_usage_flags = {
        "digital_signature": True,
        "content_commitment": False,
        "key_encipherment": True,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    }
    eku_labels = ["serverAuth"] if config.usage_preset == "server_tls" else ["clientAuth"]

    bundle = GeneratedCertBundle(
        cert_pem=cert_pem,
        key_pem=key_pem,
        combined_pem=combined_pem,
        pfx=pfx_blob,
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        serial_number=certificate.serial_number,
        common_name=config.common_name,
        dns_sans=config.dns_sans,
        ip_sans=config.ip_sans,
        key_algorithm=config.key_algorithm,
        key_size=public_key.key_size,
        usage_preset=config.usage_preset,
        mode="simple",
        is_ca=False,
        path_length=None,
        key_usage=key_usage_flags,
        extended_key_usage=eku_labels,
    )
    return bundle


def generate_self_signed_cert_advanced(config: AdvancedCertConfig) -> GeneratedCertBundle:
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=1)
    not_after = not_before + timedelta(days=config.validity_days)

    private_key = _generate_private_key(config)
    public_key = private_key.public_key()

    name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, config.common_name)]
    if config.organization:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.organization))
    if config.organizational_unit:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.organizational_unit))
    if config.country:
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, config.country))
    if config.state:
        name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.state))
    if config.locality:
        name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, config.locality))

    subject = x509.Name(name_attributes)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    san_entries: List[x509.GeneralName] = []
    for dns in config.dns_sans:
        san_entries.append(x509.DNSName(dns))
    for ip_str in config.ip_sans:
        san_entries.append(x509.IPAddress(ip_address(ip_str)))

    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    key_usage = x509.KeyUsage(
        digital_signature=config.key_usage_digital_signature,
        content_commitment=config.key_usage_non_repudiation,
        key_encipherment=config.key_usage_key_encipherment,
        data_encipherment=config.key_usage_data_encipherment,
        key_agreement=config.key_usage_key_agreement,
        key_cert_sign=config.key_usage_key_cert_sign,
        crl_sign=config.key_usage_crl_sign,
        encipher_only=config.key_usage_encipher_only,
        decipher_only=config.key_usage_decipher_only,
    )
    builder = builder.add_extension(key_usage, critical=True)

    eku_oids: List[ObjectIdentifier] = []
    if config.eku_server_auth:
        eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if config.eku_client_auth:
        eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if config.eku_code_signing:
        eku_oids.append(ExtendedKeyUsageOID.CODE_SIGNING)
    if config.eku_email_protection:
        eku_oids.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
    if config.eku_time_stamping:
        eku_oids.append(ExtendedKeyUsageOID.TIME_STAMPING)
    if config.eku_ocsp_signing:
        eku_oids.append(ExtendedKeyUsageOID.OCSP_SIGNING)
    for oid_str in config.eku_custom_oids:
        eku_oids.append(ObjectIdentifier(oid_str))
    if eku_oids:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=config.is_ca, path_length=config.path_length if config.is_ca else None),
        critical=True,
    )

    subject_key_identifier = None
    if config.subject_key_identifier == "auto":
        subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(subject_key_identifier, critical=False)

    if config.authority_key_identifier == "match_subject":
        if subject_key_identifier is None:
            subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(public_key)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=subject_key_identifier.digest,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )

    if config.crl_distribution_points:
        points = [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(url)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
            for url in config.crl_distribution_points
        ]
        builder = builder.add_extension(x509.CRLDistributionPoints(points), critical=False)

    if config.ocsp_urls:
        access_descriptions = [
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(url),
            )
            for url in config.ocsp_urls
        ]
        builder = builder.add_extension(x509.AuthorityInformationAccess(access_descriptions), critical=False)

    for custom_ext in config.custom_extensions:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier(custom_ext.oid), custom_ext.value.encode("utf-8")),
            critical=custom_ext.critical,
        )

    hash_algo = HASH_ALGORITHM_MAP[config.hash_algorithm]
    certificate = builder.sign(private_key=private_key, algorithm=hash_algo)

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM) if config.output_pem_cert else None
    key_pem = (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if config.output_pem_key
        else None
    )
    combined_pem = cert_pem + b"\n" + key_pem if cert_pem and key_pem and config.output_combined_pem else None

    pfx_blob = None
    if config.output_pfx:
        if not config.pfx_password:
            raise ValueError("PFX password is required when output_pfx is enabled.")
        encryption = serialization.BestAvailableEncryption(config.pfx_password.encode("utf-8"))
        label = (config.label or config.common_name).encode("utf-8")
        pfx_blob = pkcs12.serialize_key_and_certificates(
            name=label,
            key=private_key,
            cert=certificate,
            cas=None,
            encryption_algorithm=encryption,
        )

    key_usage_flags = {
        "digital_signature": config.key_usage_digital_signature,
        "content_commitment": config.key_usage_non_repudiation,
        "key_encipherment": config.key_usage_key_encipherment,
        "data_encipherment": config.key_usage_data_encipherment,
        "key_agreement": config.key_usage_key_agreement,
        "key_cert_sign": config.key_usage_key_cert_sign,
        "crl_sign": config.key_usage_crl_sign,
        "encipher_only": config.key_usage_encipher_only,
        "decipher_only": config.key_usage_decipher_only,
    }
    display_ekus: list[str] = []
    if config.eku_server_auth:
        display_ekus.append("serverAuth")
    if config.eku_client_auth:
        display_ekus.append("clientAuth")
    if config.eku_code_signing:
        display_ekus.append("codeSigning")
    if config.eku_email_protection:
        display_ekus.append("emailProtection")
    if config.eku_time_stamping:
        display_ekus.append("timeStamping")
    if config.eku_ocsp_signing:
        display_ekus.append("ocspSigning")
    display_ekus.extend(config.eku_custom_oids)

    bundle = GeneratedCertBundle(
        cert_pem=cert_pem,
        key_pem=key_pem,
        combined_pem=combined_pem,
        pfx=pfx_blob,
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        serial_number=certificate.serial_number,
        common_name=config.common_name,
        dns_sans=config.dns_sans,
        ip_sans=config.ip_sans,
        key_algorithm=config.key_algorithm,
        key_size=public_key.key_size,
        usage_preset="advanced",
        mode="advanced",
        is_ca=config.is_ca,
        path_length=config.path_length if config.is_ca else None,
        key_usage=key_usage_flags,
        extended_key_usage=display_ekus,
        crl_distribution_points=config.crl_distribution_points,
        ocsp_urls=config.ocsp_urls,
        custom_extension_oids=[ext.oid for ext in config.custom_extensions],
    )
    return bundle


def _generate_private_key(config: SimpleCertConfig):
    if config.key_algorithm == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=config.key_size or 2048)
    curve = CURVE_MAP[config.curve or "P-256"]
    return ec.generate_private_key(curve)
