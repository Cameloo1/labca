"""Tests for the unauthenticated /pki routes."""

from __future__ import annotations

import base64
import re
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.config import get_settings
from app.models import CAStatusEnum, CertificateAuthority
from app.schemas import ImportCAConfig, IssueFromCAConfig, RootCAConfig
from app.services import keystore
from app.services.api_token_service import create_token
from app.services.ca_service import create_root_ca, import_ca
from app.services.cert_issuance_service import issue_cert_from_ca

PEM = "application/x-pem-file"
DER_CERT = "application/pkix-cert"
DER_CRL = "application/pkix-crl"
CACHE = "public, max-age=60"


def _set_env(monkeypatch, **values: str) -> None:
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()


def _root(db_session, name="Pki Root", curve="P-256") -> CertificateAuthority:
    config = RootCAConfig(name=name, subject_cn=name, validity_years=10, key_algorithm="ECDSA", curve=curve)
    ca = create_root_ca(config, db_session)
    db_session.commit()
    return ca


def _sub(db_session, root: CertificateAuthority, name="Pki Sub", days=365) -> CertificateAuthority:
    issued = issue_cert_from_ca(
        IssueFromCAConfig(
            issuer_ca_id=root.id,
            common_name=name,
            key_algorithm="ECDSA",
            curve="P-256",
            validity_days=days,
            is_ca=True,
        ),
        root,
        db_session,
    )
    sub = import_ca(
        ImportCAConfig(
            name=name,
            cert_pem=issued.cert_pem,
            key_pem=getattr(issued, "_issued_key_pem"),
            allow_intermediate_issuance=True,
        ),
        db_session,
    )
    sub.parent_ca_id = root.id
    db_session.commit()
    return sub


def _keyless(db_session, name="Keyless") -> CertificateAuthority:
    ca = _root(db_session, name=name)
    ca.key_encrypted_pem = None
    db_session.commit()
    return ca


def _pem_certs(text: str) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(text.encode())


def _use_issuer(monkeypatch, name: str) -> None:
    _set_env(monkeypatch, WORKLOAD_ISSUER_CA_NAME=name)


def test_index_json_lists_keyed_cas(client, db_session, monkeypatch):
    first = _root(db_session, name="Alpha")
    second = _root(db_session, name="Beta")
    _keyless(db_session, name="Gamma")

    response = client.get("/pki/index.json")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == CACHE
    body = response.json()
    assert set(body) == {"generated_at", "trust_bundle_url", "workload_issuer_ca_id", "root", "cas"}
    assert body["root"] is None
    assert body["workload_issuer_ca_id"] is None
    assert body["trust_bundle_url"] == "/pki/trust-bundle.pem"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", body["generated_at"])
    assert [entry["name"] for entry in body["cas"]] == ["Alpha", "Beta"]
    entry = body["cas"][0]
    assert set(entry) == {
        "id",
        "name",
        "subject",
        "sha256_fingerprint",
        "not_before",
        "not_after",
        "status",
        "urls",
    }
    assert entry["id"] == first.id
    cert = x509.load_pem_x509_certificate(first.cert_pem.encode())
    assert entry["sha256_fingerprint"] == cert.fingerprint(hashes.SHA256()).hex()
    assert entry["status"] == "ACTIVE"
    assert entry["subject"] == cert.subject.rfc4514_string()
    assert entry["urls"] == {
        "ca_pem": f"/pki/cas/{first.id}/ca.pem",
        "ca_der": f"/pki/cas/{first.id}/ca.der",
        "chain_pem": f"/pki/cas/{first.id}/chain.pem",
        "crl_der": f"/pki/cas/{first.id}/crl.der",
        "crl_pem": f"/pki/cas/{first.id}/crl.pem",
    }
    assert body["cas"][1]["id"] == second.id

    _set_env(monkeypatch, PUBLIC_BASE_URL="https://pki.example.test")
    absolute = client.get("/pki/index.json").json()
    assert absolute["trust_bundle_url"] == "https://pki.example.test/pki/trust-bundle.pem"
    assert absolute["cas"][0]["urls"]["crl_der"] == f"https://pki.example.test/pki/cas/{first.id}/crl.der"


def test_trust_bundle_contains_only_active_self_signed(client, db_session):
    empty = client.get("/pki/trust-bundle.pem")
    assert empty.status_code == 404
    assert empty.headers["cache-control"] == "no-store"

    root = _root(db_session, name="Active Root")
    _sub(db_session, root)
    disabled = _root(db_session, name="Disabled Root")
    disabled.status = CAStatusEnum.DISABLED
    db_session.commit()

    response = client.get("/pki/trust-bundle.pem")

    assert response.status_code == 200
    assert response.headers["content-type"] == PEM
    assert response.headers["cache-control"] == CACHE
    certs = _pem_certs(response.text)
    assert [cert.subject.rfc4514_string() for cert in certs] == ["CN=Active Root"]


def test_issuing_routes(client, db_session, monkeypatch):
    root = _root(db_session, name="Pki Root")
    sub = _sub(db_session, root, name="Issuing Sub")
    _use_issuer(monkeypatch, "Issuing Sub")

    ca_pem = client.get("/pki/issuing/ca.pem")
    ca_der = client.get("/pki/issuing/ca.der")
    chain = client.get("/pki/issuing/chain.pem")
    crl_der = client.get("/pki/issuing/crl.der")
    crl_pem = client.get("/pki/issuing/crl.pem")

    for response, content_type in (
        (ca_pem, PEM),
        (ca_der, DER_CERT),
        (chain, PEM),
        (crl_der, DER_CRL),
        (crl_pem, PEM),
    ):
        assert response.status_code == 200
        assert response.headers["content-type"] == content_type
        assert response.headers["cache-control"] == CACHE
    sub_cert = x509.load_pem_x509_certificate(sub.cert_pem.encode())
    assert x509.load_pem_x509_certificate(ca_pem.content) == sub_cert
    assert ca_der.content == sub_cert.public_bytes(serialization.Encoding.DER)
    assert _pem_certs(chain.text) == [sub_cert]
    crl = x509.load_der_x509_crl(crl_der.content)
    assert crl.is_signature_valid(sub_cert.public_key())
    assert crl_pem.text.startswith("-----BEGIN X509 CRL-----")
    assert x509.load_pem_x509_crl(crl_pem.content).public_bytes(serialization.Encoding.DER) == crl_der.content
    index = client.get("/pki/index.json").json()
    assert index["workload_issuer_ca_id"] == sub.id


def test_issuing_404_when_unset_missing_or_ambiguous(client, db_session, monkeypatch):
    _root(db_session, name="Dup")
    _root(db_session, name="Dup")

    assert client.get("/pki/issuing/ca.pem").status_code == 404

    _use_issuer(monkeypatch, "Nobody")
    assert client.get("/pki/issuing/ca.pem").status_code == 404

    _use_issuer(monkeypatch, "Dup")
    response = client.get("/pki/issuing/ca.pem")
    assert response.status_code == 404
    assert response.text == "Not found\n"
    assert client.get("/pki/issuing/crl.der").status_code == 404


def test_cas_routes_unknown_and_keyless_404(client, db_session):
    keyless = _keyless(db_session)
    ids = [str(uuid.uuid4()), keyless.id, "x" * 37]
    files = ["ca.pem", "ca.der", "chain.pem", "crl.der", "crl.pem"]

    for ca_id in ids:
        for name in files:
            response = client.get(f"/pki/cas/{ca_id}/{name}")
            assert response.status_code == 404
            assert response.headers["content-type"].startswith("text/plain")
            assert response.text == "Not found\n"
            assert response.headers["cache-control"] == "no-store"


def test_cas_routes_serve_keyed_ca(client, db_session):
    root = _root(db_session)
    sub = _sub(db_session, root)

    chain = client.get(f"/pki/cas/{sub.id}/chain.pem")
    der = client.get(f"/pki/cas/{sub.id}/ca.der")
    pem = client.get(f"/pki/cas/{sub.id}/ca.pem")

    sub_cert = x509.load_pem_x509_certificate(sub.cert_pem.encode())
    assert _pem_certs(chain.text) == [sub_cert]
    assert der.headers["content-type"] == DER_CERT
    assert pem.headers["content-type"] == PEM
    assert pem.text == sub.cert_pem


def test_chain_includes_intermediates_but_not_root(client, db_session):
    root = _root(db_session)
    middle = _sub(db_session, root, name="Pki Middle")
    leaf_ca = _sub(db_session, middle, name="Pki Leaf CA", days=30)

    chain = client.get(f"/pki/cas/{leaf_ca.id}/chain.pem")

    assert chain.status_code == 200
    expected = [x509.load_pem_x509_certificate(ca.cert_pem.encode()) for ca in (leaf_ca, middle)]
    assert _pem_certs(chain.text) == expected


def test_crl_reflects_revocation(client, db_session):
    ca = _root(db_session)
    _, raw = create_token("tok", {"issue": True, "read": True, "revoke": True}, None, db_session, policy=None)
    headers = {"Authorization": f"Bearer {raw}"}
    issued = client.post(
        "/api/v1/certificates",
        headers=headers,
        json={
            "issuer_ca_id": ca.id,
            "common_name": "rev.lab.example",
            "key_algorithm": "ECDSA",
            "curve": "P-256",
            "validity_days": 1,
        },
    )
    assert issued.status_code == 201
    cert_id = issued.json()["certificate_id"]
    before = x509.load_der_x509_crl(client.get(f"/pki/cas/{ca.id}/crl.der").content)
    assert len(list(before)) == 0

    revoked = client.post(f"/api/v1/certificates/{cert_id}/revoke", headers=headers, json={"reason": "keyCompromise"})
    assert revoked.status_code == 200
    serial = revoked.json()["serial_hex"]

    crl = x509.load_der_x509_crl(client.get(f"/pki/cas/{ca.id}/crl.der").content)
    entries = list(crl)
    assert [entry.serial_number for entry in entries] == [int(serial, 16)]
    reason = entries[0].extensions.get_extension_for_class(x509.CRLReason).value.reason
    assert reason == x509.ReasonFlags.key_compromise
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 2


def test_crl_route_503_when_key_unavailable(client, db_session, monkeypatch):
    ca = _root(db_session)
    monkeypatch.delenv("LABCA_KEK_TEST_1", raising=False)
    monkeypatch.setenv("LABCA_KEK_OTHER_1", base64.b64encode(bytes(range(1, 33))).decode())
    monkeypatch.setenv("LABCA_ACTIVE_KEK_ID", "other-1")
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()

    for name in ("crl.der", "crl.pem"):
        response = client.get(f"/pki/cas/{ca.id}/{name}")
        assert response.status_code == 503
        assert response.text == "CRL temporarily unavailable\n"
        assert response.headers["cache-control"] == "no-store"


def test_root_static_files(client, tmp_path, monkeypatch):
    assert client.get("/pki/root/ca.pem").status_code == 404
    assert client.get("/pki/root/crl.der").status_code == 404

    _set_env(monkeypatch, PKI_STATIC_DIR=str(tmp_path / "missing"))
    assert client.get("/pki/root/ca.pem").status_code == 404
    assert client.get("/pki/index.json").json()["root"] is None

    (tmp_path / "root-ca.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n")
    (tmp_path / "root-crl.der").write_bytes(b"\x30\x03\x02\x01\x00")
    _set_env(monkeypatch, PKI_STATIC_DIR=str(tmp_path), PUBLIC_BASE_URL="https://pki.example.test")

    pem = client.get("/pki/root/ca.pem")
    crl = client.get("/pki/root/crl.der")
    assert pem.status_code == 200 and pem.headers["content-type"] == PEM
    assert pem.headers["cache-control"] == CACHE
    assert pem.content.startswith(b"-----BEGIN CERTIFICATE-----")
    assert crl.status_code == 200 and crl.headers["content-type"] == DER_CRL
    assert crl.content == b"\x30\x03\x02\x01\x00"
    assert client.get("/pki/index.json").json()["root"] == {
        "ca_pem_url": "https://pki.example.test/pki/root/ca.pem",
        "crl_der_url": "https://pki.example.test/pki/root/crl.der",
    }

    (tmp_path / "root-crl.der").write_bytes(b"\x00" * (2 * 1024 * 1024))
    big = client.get("/pki/root/crl.der")
    assert big.status_code == 404 and big.text == "Not found\n"


def test_root_static_directory_in_place_of_file_is_404(client, tmp_path, monkeypatch):
    (tmp_path / "root-ca.pem").mkdir()
    _set_env(monkeypatch, PKI_STATIC_DIR=str(tmp_path))

    assert client.get("/pki/root/ca.pem").status_code == 404
    assert client.get("/pki/index.json").json()["root"] is None


def test_pki_routes_need_no_auth(client, db_session, monkeypatch, tmp_path):
    root = _root(db_session, name="Open Root")
    (tmp_path / "root-ca.pem").write_bytes(b"pem")
    (tmp_path / "root-crl.der").write_bytes(b"der")
    _set_env(monkeypatch, WORKLOAD_ISSUER_CA_NAME="Open Root", PKI_STATIC_DIR=str(tmp_path))
    paths = [
        "/pki/index.json",
        "/pki/trust-bundle.pem",
        "/pki/issuing/ca.pem",
        "/pki/issuing/ca.der",
        "/pki/issuing/chain.pem",
        "/pki/issuing/crl.der",
        "/pki/issuing/crl.pem",
        "/pki/root/ca.pem",
        "/pki/root/crl.der",
    ] + [f"/pki/cas/{root.id}/{name}" for name in ("ca.pem", "ca.der", "chain.pem", "crl.der", "crl.pem")]

    for path in paths:
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 200, path
        assert "set-cookie" not in response.headers
