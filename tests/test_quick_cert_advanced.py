from __future__ import annotations

import re

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier


def _extract_certificate(response_text: str) -> x509.Certificate:
    cert_match = re.search(
        r'id="cert-pem"[^>]*>(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
        response_text,
        re.S,
    )
    assert cert_match, "Certificate PEM block not found in response"
    cert_pem = cert_match.group(1).strip().encode("utf-8")
    return x509.load_pem_x509_certificate(cert_pem)


def test_advanced_ca_certificate_has_basic_constraints_and_key_usage(client, csrf) -> None:
    payload = {
        "mode": "advanced",
        "common_name": "LabCA Root",
        "dns_sans": "",
        "ip_sans": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "365",
        "output_pem_cert": "true",
        "output_pem_key": "true",
        "is_ca": "true",
        "path_length": "1",
        "key_usage_key_cert_sign": "true",
        "key_usage_crl_sign": "true",
        "key_usage_digital_signature": "true",
        "subject_key_identifier": "auto",
        "authority_key_identifier": "match_subject",
    }
    response = client.post("/quick-cert", data={**payload, **csrf(client)})
    assert response.status_code == 200
    certificate = _extract_certificate(response.text)

    basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic_constraints.ca is True
    assert basic_constraints.path_length == 1

    key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.key_cert_sign
    assert key_usage.crl_sign


def test_advanced_custom_eku_and_oid(client, csrf) -> None:
    payload = {
        "mode": "advanced",
        "common_name": "advanced.leaf.local",
        "dns_sans": "advanced.leaf.local",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "90",
        "output_pem_cert": "true",
        "output_pem_key": "true",
        "is_ca": "",
        "key_usage_digital_signature": "true",
        "key_usage_key_encipherment": "true",
        "eku_server_auth": "true",
        "eku_client_auth": "",
        "eku_custom_oids": "1.2.3.4.5",
        "subject_key_identifier": "auto",
        "authority_key_identifier": "omit",
    }
    response = client.post("/quick-cert", data={**payload, **csrf(client)})
    assert response.status_code == 200
    certificate = _extract_certificate(response.text)

    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ObjectIdentifier("1.2.3.4.5") in eku


def test_invalid_ca_without_key_cert_sign_is_rejected(client, csrf) -> None:
    payload = {
        "mode": "advanced",
        "common_name": "Bad CA",
        "validity_days": "365",
        "output_pem_cert": "true",
        "is_ca": "true",
        "key_usage_key_cert_sign": "",
    }
    response = client.post("/quick-cert", data={**payload, **csrf(client)})
    assert response.status_code == 400
    assert "Key Cert Sign" in response.text
