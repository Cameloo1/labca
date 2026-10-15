"""Tests for CRL Distribution Point and AIA extensions on issued certificates."""

from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.schemas import IssueFromCAConfig, RootCAConfig
from app.services.ca_service import create_root_ca
from app.services.cert_issuance_service import issue_cert_from_ca
from app.services.csr_signing_service import issue_leaf_for_public_key

BASE = "https://labca.example.test"


def _ca(db_session):
    ca = create_root_ca(
        RootCAConfig(name="Cdp Root", subject_cn="Cdp Root", validity_years=5, key_algorithm="ECDSA", curve="P-256"),
        db_session,
    )
    db_session.commit()
    return ca


def _set_base(monkeypatch, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    else:
        monkeypatch.setenv("PUBLIC_BASE_URL", value)
    get_settings.cache_clear()


def _from_ca(db_session, ca) -> x509.Certificate:
    record = issue_cert_from_ca(
        IssueFromCAConfig(
            issuer_ca_id=ca.id, common_name="leaf.lab", key_algorithm="ECDSA", curve="P-256", validity_days=30
        ),
        ca,
        db_session,
    )
    return x509.load_pem_x509_certificate(record.cert_pem.encode())


def _from_csr(db_session, ca) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    record = issue_leaf_for_public_key(
        db_session,
        ca,
        key.public_key(),
        common_name="csr.lab",
        dns_sans=["csr.lab"],
        ip_sans=[],
        uri_sans=[],
        validity=timedelta(days=30),
        usage_preset="server_tls",
        environment_tags=[],
    )
    return x509.load_pem_x509_certificate(record.cert_pem.encode())


def _check_present(cert: x509.Certificate, ca_id: str) -> None:
    cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    assert cdp.critical is False and aia.critical is False
    assert [name.value for point in cdp.value for name in point.full_name] == [f"{BASE}/pki/cas/{ca_id}/crl.der"]
    descriptions = list(aia.value)
    assert len(descriptions) == 1
    assert descriptions[0].access_method == AuthorityInformationAccessOID.CA_ISSUERS
    assert descriptions[0].access_location.value == f"{BASE}/pki/cas/{ca_id}/ca.der"


def test_issue_from_ca_has_cdp_and_aia_when_base_url_set(db_session, monkeypatch):
    ca = _ca(db_session)
    _set_base(monkeypatch, BASE)

    _check_present(_from_ca(db_session, ca), ca.id)


def test_csr_signed_leaf_has_cdp_and_aia(db_session, monkeypatch):
    ca = _ca(db_session)
    _set_base(monkeypatch, BASE)

    _check_present(_from_csr(db_session, ca), ca.id)


def test_no_cdp_without_base_url(db_session, monkeypatch):
    ca = _ca(db_session)
    _set_base(monkeypatch, None)

    for cert in (_from_ca(db_session, ca), _from_csr(db_session, ca)):
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        with pytest.raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)


def test_public_base_url_validation():
    assert Settings(PUBLIC_BASE_URL="https://x.test/").PUBLIC_BASE_URL == "https://x.test"
    assert Settings(PUBLIC_BASE_URL="http://x.test:8080").PUBLIC_BASE_URL == "http://x.test:8080"
    assert Settings(PUBLIC_BASE_URL="").PUBLIC_BASE_URL is None
    for bad in ("ftp://x", "https://x.test/path", "https://x.test/?q=1", "https://x.test/#frag", "https://"):
        with pytest.raises(ValidationError, match="PUBLIC_BASE_URL must be an http"):
            Settings(PUBLIC_BASE_URL=bad)
