"""Tests for POST /api/v1/certificates/sign and the CSR signing service."""

from __future__ import annotations

import ipaddress
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.models import AuditLog, AuditStatus, CAStatusEnum, Certificate, CertificateAuthority
from app.schemas import RootCAConfig, TokenPolicy
from app.services.api_token_service import create_token
from app.services.ca_service import create_root_ca
from app.services.csr_signing_service import (
    MAX_CSR_PEM_BYTES,
    CsrError,
    issue_leaf_for_public_key,
    load_and_verify_csr,
)

SPIFFE = "spiffe://lab.example/ns/app/sa/web"
UNSUPPORTED_KEY = "Unsupported key type. Use ECDSA P-256 or P-384, or RSA 2048 to 8192 bits."


def _make_ca(db_session, *, curve: str = "P-256", validity_years: int = 5) -> CertificateAuthority:
    config = RootCAConfig(
        name=f"CSR Root {curve}",
        subject_cn=f"CSR Root {curve}",
        validity_years=validity_years,
        key_algorithm="ECDSA",
        curve=curve,  # type: ignore[arg-type]  # str is validated by the Literal at runtime
    )
    ca = create_root_ca(config, db_session)
    db_session.commit()
    db_session.refresh(ca)
    return ca


def _token(db_session, *, issue: bool = True, policy: dict | None = None):
    token, raw = create_token(
        "csr-client", {"issue": issue, "read": True, "revoke": True}, None, db_session, policy=policy
    )
    return token, {"Authorization": f"Bearer {raw}"}


def _csr(
    key=None,
    *,
    cn: str | None = "svc.lab.example",
    dns=("svc.lab.example",),
    ips=(),
    uris=(),
    extra_names=(),
    sign_hash=None,
) -> tuple[str, object]:
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]) if cn is not None else x509.Name([])
    builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    entries: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
    entries += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    entries += [x509.UniformResourceIdentifier(u) for u in uris]
    entries += list(extra_names)
    if entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(entries), critical=False)
    if sign_hash is None:
        sign_hash = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    csr = builder.sign(key, sign_hash)
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


def _tamper(csr_pem: str) -> str:
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01  # the signature bit string is the last element of the DER structure
    tampered = x509.load_der_x509_csr(bytes(der))
    assert not tampered.is_signature_valid
    return tampered.public_bytes(serialization.Encoding.PEM).decode()


def _sign(client, headers, ca_id, csr_pem, *, hours=24, preset="server_tls"):
    return client.post(
        "/api/v1/certificates/sign",
        headers=headers,
        json={"issuer_ca_id": ca_id, "csr_pem": csr_pem, "validity_hours": hours, "usage_preset": preset},
    )


@pytest.mark.parametrize(
    "preset,expected",
    [
        ("server_tls", [ExtendedKeyUsageOID.SERVER_AUTH]),
        ("client_tls", [ExtendedKeyUsageOID.CLIENT_AUTH]),
        ("mtls", [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
    ],
)
def test_sign_ec_p256_csr(client, db_session, preset, expected):
    ca = _make_ca(db_session)
    token, headers = _token(db_session)
    csr_pem, key = _csr(dns=("svc.lab.example", "alt.lab.example"), ips=("10.0.0.7",), uris=(SPIFFE,))

    response = _sign(client, headers, ca.id, csr_pem, hours=48, preset=preset)

    assert response.status_code == 201
    body = response.json()
    assert "private_key_pem" not in body
    assert set(body) == {"certificate_id", "serial_hex", "not_before", "not_after", "certificate_pem", "chain_pem"}
    leaf = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
    leaf.verify_directly_issued_by(ca_cert)
    assert leaf.public_key().public_numbers() == key.public_key().public_numbers()
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.critical is False
    assert san.value.get_values_for_type(x509.DNSName) == ["svc.lab.example", "alt.lab.example"]
    assert san.value.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("10.0.0.7")]
    assert san.value.get_values_for_type(x509.UniformResourceIdentifier) == [SPIFFE]
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert eku.critical is False
    assert list(eku.value) == expected
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical is True and bc.value.ca is False and bc.value.path_length is None
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical is True
    assert ku.value.digital_signature is True
    assert ku.value.key_encipherment is False
    assert ku.value.key_cert_sign is False and ku.value.crl_sign is False
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc == timedelta(hours=48)
    leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert leaf.subject.rfc4514_string() == "CN=svc.lab.example"
    assert body["chain_pem"] == body["certificate_pem"].rstrip("\n") + "\n" + ca.cert_pem.rstrip("\n") + "\n"
    assert body["chain_pem"].startswith(body["certificate_pem"])

    row = db_session.get(Certificate, body["certificate_id"])
    assert row.stored_key_encrypted_pem is None
    assert row.issued_by_token_id == token.id
    assert row.san_uris == [SPIFFE]
    assert row.san_dns == ["svc.lab.example", "alt.lab.example"]
    assert row.san_ips == ["10.0.0.7"]
    assert row.serial_number == body["serial_hex"]
    assert row.environment_tags == ["csr"]
    assert row.owner == "csr-client"
    assert row.key_algorithm == "ECDSA" and row.key_size == 256


def test_sign_rsa_2048_csr(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_pem, _ = _csr(key)

    response = _sign(client, headers, ca.id, csr_pem)

    assert response.status_code == 201
    leaf = x509.load_pem_x509_certificate(response.json()["certificate_pem"].encode())
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature is True and ku.key_encipherment is True
    assert db_session.get(Certificate, response.json()["certificate_id"]).key_algorithm == "RSA"


def test_sign_with_p384_ca_uses_sha384(client, db_session):
    ca = _make_ca(db_session, curve="P-384")
    _, headers = _token(db_session)
    csr_pem, _ = _csr()

    response = _sign(client, headers, ca.id, csr_pem)

    assert response.status_code == 201
    leaf = x509.load_pem_x509_certificate(response.json()["certificate_pem"].encode())
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA384)


def test_sign_with_p256_ca_uses_sha256(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    response = _sign(client, headers, ca.id, _csr()[0])
    leaf = x509.load_pem_x509_certificate(response.json()["certificate_pem"].encode())
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA256)


def test_invalid_csr_signature_rejected(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    response = _sign(client, headers, ca.id, _tamper(_csr()[0]))
    assert response.status_code == 400
    assert response.json()["detail"] == "CSR signature is invalid."
    assert db_session.query(Certificate).count() == 0


def test_garbage_csr_rejected(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    response = _sign(client, headers, ca.id, "not a csr")
    assert response.status_code == 400
    assert response.json()["detail"] == "CSR could not be parsed."


def test_oversized_csr_rejected(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    response = _sign(client, headers, ca.id, "A" * (MAX_CSR_PEM_BYTES + 1))
    assert response.status_code == 400
    assert response.json()["detail"] == "CSR is too large."


@pytest.mark.parametrize(
    "make_key",
    [
        lambda: rsa.generate_private_key(public_exponent=65537, key_size=1024),
        lambda: ec.generate_private_key(ec.SECP521R1()),
        lambda: ed25519.Ed25519PrivateKey.generate(),
    ],
    ids=["rsa1024", "p521", "ed25519"],
)
def test_disallowed_key_types_rejected(client, db_session, make_key):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    csr_pem, _ = _csr(make_key())
    response = _sign(client, headers, ca.id, csr_pem)
    assert response.status_code == 400
    assert response.json()["detail"] == UNSUPPORTED_KEY


def test_unsupported_san_type_rejected(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    csr_pem, _ = _csr(extra_names=[x509.RFC822Name("a@lab.example")])
    response = _sign(client, headers, ca.id, csr_pem)
    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported SAN type in CSR."


def test_csr_with_invalid_uri_san_rejected(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    csr_pem, _ = _csr(uris=("http://insecure.example/",))
    response = _sign(client, headers, ca.id, csr_pem)
    assert response.status_code == 400
    assert response.json()["detail"] == "Only spiffe:// and https:// URI SANs are allowed."


def test_common_name_falls_back_to_first_dns_then_uri(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    dns_resp = _sign(client, headers, ca.id, _csr(cn=None, dns=("only.lab.example",))[0])
    assert dns_resp.status_code == 201
    assert db_session.get(Certificate, dns_resp.json()["certificate_id"]).common_name == "only.lab.example"
    long_uri = "spiffe://lab.example/ns/" + "a" * 60
    uri_resp = _sign(client, headers, ca.id, _csr(cn=None, dns=(), uris=(long_uri,))[0])
    assert uri_resp.status_code == 400  # a URI longer than 64 characters cannot be a CN
    assert uri_resp.json()["detail"] == "Common name must be 1 to 64 characters."
    short = "spiffe://a.example/b"
    short_resp = _sign(client, headers, ca.id, _csr(cn=None, dns=(), uris=(short,))[0])
    assert short_resp.status_code == 201
    assert db_session.get(Certificate, short_resp.json()["certificate_id"]).common_name == short


def test_csr_without_cn_or_san_rejected(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    response = _sign(client, headers, ca.id, _csr(cn=None, dns=())[0])
    assert response.status_code == 400
    assert response.json()["detail"] == "CSR has no subject CN or SAN."


def test_sign_policy_denies_dns_and_uri_and_validity(client, db_session):
    ca = _make_ca(db_session)
    policy = TokenPolicy(
        allowed_dns_suffixes=["lab.example"],
        allowed_uri_prefixes=["spiffe://lab.example/ns/app/"],
        max_validity_hours=24,
    ).model_dump()
    _, headers = _token(db_session, policy=policy)

    dns = _sign(client, headers, ca.id, _csr(cn="evil.example", dns=("evil.example",))[0])
    uri = _sign(client, headers, ca.id, _csr(dns=("a.lab.example",), uris=("spiffe://lab.example/ns/other/x",))[0])
    hours = _sign(client, headers, ca.id, _csr(dns=("a.lab.example",))[0], hours=25)
    ip = _sign(client, headers, ca.id, _csr(dns=("a.lab.example",), ips=("10.0.0.1",))[0])

    assert dns.status_code == uri.status_code == hours.status_code == ip.status_code == 403
    assert dns.json()["detail"] == "DNS SAN 'evil.example' is not allowed by the token policy."
    assert uri.json()["detail"] == "URI SAN 'spiffe://lab.example/ns/other/x' is not allowed by the token policy."
    assert hours.json()["detail"] == ("Requested validity of 25 hours exceeds the token policy maximum of 24 hours.")
    assert ip.json()["detail"] == "IP SANs are not allowed by the token policy."
    rows = db_session.query(AuditLog).filter(AuditLog.action == "SIGN_CSR").all()
    assert len(rows) == 4
    assert all(row.status == AuditStatus.FAILURE for row in rows)
    assert {row.details_json["reason"] for row in rows} == {
        dns.json()["detail"],
        uri.json()["detail"],
        hours.json()["detail"],
        ip.json()["detail"],
    }
    assert db_session.query(Certificate).count() == 0


def test_sign_policy_allows_matching_request(client, db_session):
    ca = _make_ca(db_session)
    policy = TokenPolicy(
        allowed_dns_suffixes=["lab.example"], allowed_uri_prefixes=["spiffe://lab.example/"], max_validity_hours=24
    ).model_dump()
    _, headers = _token(db_session, policy=policy)
    response = _sign(client, headers, ca.id, _csr(dns=("a.lab.example",), uris=(SPIFFE,))[0], hours=24)
    assert response.status_code == 201


def test_sign_requires_issue_permission(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session, issue=False)
    response = _sign(client, headers, ca.id, _csr()[0])
    assert response.status_code == 403
    assert response.json()["detail"] == "API token is not permitted to issue certificates."


def test_sign_unknown_ca(client, db_session):
    _, headers = _token(db_session)
    response = _sign(client, headers, "missing-ca", _csr()[0])
    assert response.status_code == 404
    assert response.json()["detail"] == "Issuer CA not found."


def test_sign_validity_beyond_ca(client, db_session):
    ca = _make_ca(db_session, validity_years=1)
    _, headers = _token(db_session)
    response = _sign(client, headers, ca.id, _csr()[0], hours=87600)
    assert response.status_code == 400
    assert response.json()["detail"] == "Requested validity exceeds issuer CA validity."


def test_sign_inactive_ca_rejected(client, db_session):
    ca = _make_ca(db_session)
    ca.status = CAStatusEnum.DISABLED
    db_session.commit()
    _, headers = _token(db_session)
    response = _sign(client, headers, ca.id, _csr()[0])
    assert response.status_code == 400
    assert response.json()["detail"] == "Issuer CA is not active."


def test_sign_without_auth(client, db_session):
    ca = _make_ca(db_session)
    response = client.post(
        "/api/v1/certificates/sign",
        json={"issuer_ca_id": ca.id, "csr_pem": _csr()[0], "validity_hours": 24},
    )
    assert response.status_code == 401


def test_sign_rejects_out_of_range_validity(client, db_session):
    ca = _make_ca(db_session)
    _, headers = _token(db_session)
    assert _sign(client, headers, ca.id, _csr()[0], hours=0).status_code == 422
    assert _sign(client, headers, ca.id, _csr()[0], hours=87601).status_code == 422
    assert _sign(client, headers, ca.id, _csr()[0], preset="bogus").status_code == 422


def test_sign_success_audited(client, db_session):
    ca = _make_ca(db_session)
    token, headers = _token(db_session)
    response = _sign(client, headers, ca.id, _csr()[0])
    assert response.status_code == 201
    rows = db_session.query(AuditLog).filter(AuditLog.action == "SIGN_CSR").all()
    assert len(rows) == 1
    row = rows[0]
    assert row.status == AuditStatus.SUCCESS
    assert row.actor_id == token.token_prefix
    assert row.target_id == response.json()["certificate_id"]
    assert row.details_json == {
        "issuer_ca_id": ca.id,
        "common_name": "svc.lab.example",
        "serial_hex": response.json()["serial_hex"],
    }


def test_service_rejects_unknown_preset_and_bad_cn(db_session):
    ca = _make_ca(db_session)
    info = load_and_verify_csr(_csr()[0])
    common = dict(
        dns_sans=[],
        ip_sans=[],
        uri_sans=[],
        validity=timedelta(hours=1),
        environment_tags=[],
    )
    with pytest.raises(ValueError, match="Unknown usage preset."):
        issue_leaf_for_public_key(db_session, ca, info.public_key, common_name="a", usage_preset="nope", **common)
    with pytest.raises(ValueError, match="Common name must be 1 to 64 characters."):
        issue_leaf_for_public_key(db_session, ca, info.public_key, common_name="", usage_preset="mtls", **common)
    with pytest.raises(ValueError, match="Common name must be 1 to 64 characters."):
        issue_leaf_for_public_key(db_session, ca, info.public_key, common_name="a" * 65, usage_preset="mtls", **common)


def test_load_and_verify_csr_extracts_fields():
    pem, key = _csr(cn="cn.lab.example", dns=("a.lab.example",), ips=("10.0.0.9", "::1"), uris=(SPIFFE,))
    info = load_and_verify_csr(pem)
    assert info.common_name == "cn.lab.example"
    assert info.dns_sans == ["a.lab.example"]
    assert info.ip_sans == ["10.0.0.9", "::1"]
    assert info.uri_sans == [SPIFFE]
    assert info.key_algorithm == "ECDSA" and info.key_size == 256
    with pytest.raises(CsrError):
        load_and_verify_csr("")
