from __future__ import annotations

import re
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def test_quick_cert_simple_flow(client) -> None:
    payload = {
        "common_name": "example.local",
        "dns_sans": "example.local",
        "ip_sans": "",
        "organization": "",
        "organizational_unit": "",
        "country": "",
        "state": "",
        "locality": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "30",
        "usage_preset": "server_tls",
        "output_pem_cert": "true",
        "output_pem_key": "true",
        "output_combined_pem": "",
        "output_pfx": "",
        "pfx_password": "",
        "pfx_password_confirm": "",
        "label": "Example Lab",
    }

    response = client.post("/quick-cert", data=payload)
    assert response.status_code == 200
    assert "example.local" in response.text
    assert "Download certificate" in response.text

    cert_match = re.search(
        r'id="cert-pem"[^>]*>(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
        response.text,
        re.S,
    )
    assert cert_match, "Certificate PEM block not found in response"
    cert_pem = cert_match.group(1).strip().encode("utf-8")

    certificate = x509.load_pem_x509_certificate(cert_pem)
    cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == payload["common_name"]

    now = datetime.now(timezone.utc)
    assert certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc

    key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature
    assert key_usage.key_encipherment

    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_quick_cert_client_tls_preset(client) -> None:
    """Test client TLS preset includes clientAuth EKU."""
    payload = {
        "common_name": "client.example.local",
        "dns_sans": "",
        "ip_sans": "",
        "organization": "",
        "organizational_unit": "",
        "country": "",
        "state": "",
        "locality": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "curve": "P-256",
        "hash_algorithm": "SHA256",
        "validity_days": "30",
        "usage_preset": "client_tls",
        "output_pem_cert": "true",
        "output_pem_key": "true",
        "output_combined_pem": "",
        "output_pfx": "",
        "pfx_password": "",
        "pfx_password_confirm": "",
        "label": "Client Cert",
    }

    response = client.post("/quick-cert", data=payload)
    assert response.status_code == 200

    cert_match = re.search(
        r'id="cert-pem"[^>]*>(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
        response.text,
        re.S,
    )
    assert cert_match, "Certificate PEM block not found in response"
    cert_pem = cert_match.group(1).strip().encode("utf-8")

    certificate = x509.load_pem_x509_certificate(cert_pem)
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_quick_cert_missing_cn_validation(client) -> None:
    """Test form validation: missing CN returns error."""
    payload = {
        "common_name": "",  # Missing CN
        "dns_sans": "",
        "ip_sans": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "hash_algorithm": "SHA256",
        "validity_days": "30",
        "usage_preset": "server_tls",
        "output_pem_cert": "true",
    }

    response = client.post("/quick-cert", data=payload)
    assert response.status_code == 400
    assert "common name" in response.text.lower() or "CN" in response.text


def test_quick_cert_no_output_formats_validation(client) -> None:
    """Test form validation: no output formats selected returns error."""
    payload = {
        "common_name": "test.local",
        "dns_sans": "",
        "ip_sans": "",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "hash_algorithm": "SHA256",
        "validity_days": "30",
        "usage_preset": "server_tls",
        "output_pem_cert": "",
        "output_pem_key": "",
        "output_combined_pem": "",
        "output_pfx": "",
    }

    response = client.post("/quick-cert", data=payload)
    assert response.status_code == 400
    assert "output" in response.text.lower() or "format" in response.text.lower()
