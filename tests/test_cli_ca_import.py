"""Tests for ``python -m app.cli ca import-root-cert`` and ``ca import``."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from sqlalchemy import select

from app import cli
from app.config import get_settings
from app.models import AuditLog, CASourceTypeEnum, CAStatusEnum, CertificateAuthority
from app.services import keystore, pki_service
from app.services.keystore import KeyRing
from tests.cli_support import (
    ISSUING_NAME,
    ROOT_NAME,
    cert_pem,
    key_pem,
    make_ceremony,
    run,
    run_json,
    self_signed,
    set_stdin,
)

KEK = bytes(range(32, 64))


@pytest.fixture(scope="module")
def cer(tmp_path_factory) -> Path:
    return make_ceremony(tmp_path_factory.mktemp("ceremony") / "cer")


@pytest.fixture(autouse=True)
def _tables(db_session):
    """Every test here needs the schema; db_session creates and drops it."""
    yield


@pytest.fixture
def ring() -> KeyRing:
    return KeyRing({"k1": KEK}, active_kek_id="k1")


def _import_root(capsys, SessionLocal, cer: Path) -> dict:
    code, out = run_json(
        capsys,
        ["ca", "import-root-cert", "--name", ROOT_NAME, "--cert", str(cer / "root-ca.pem")],
        session_factory=SessionLocal,
    )
    assert code == 0
    return out


def _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer: Path, key: bytes | None = None, chain=None):
    set_stdin(monkeypatch, key if key is not None else (cer / "issuing-ca.key.pem").read_bytes())
    return run(
        capsys,
        [
            "ca",
            "import",
            "--name",
            ISSUING_NAME,
            "--cert",
            str(cer / "issuing-ca.pem"),
            "--chain",
            str(chain or cer / "chain.pem"),
            "--key-stdin",
        ],
        session_factory=SessionLocal,
        keyring=ring,
    )


def _files(root: Path) -> set[Path]:
    return {p for p in root.rglob("*") if p.is_file()}


# --- import-root-cert -------------------------------------------------------------------


def test_import_root_cert_happy_path(capsys, db_session, SessionLocal, cer):
    out = _import_root(capsys, SessionLocal, cer)
    cert = x509.load_pem_x509_certificate((cer / "root-ca.pem").read_bytes())
    assert set(out) == {"ca_id", "name", "sha256_fingerprint"}
    assert out["name"] == ROOT_NAME
    assert out["sha256_fingerprint"] == pki_service.sha256_fingerprint_hex(cert)

    db_session.expire_all()
    row = db_session.get(CertificateAuthority, out["ca_id"])
    assert row is not None
    assert row.source_type == CASourceTypeEnum.EXTERNAL_IMPORTED
    assert row.parent_ca_id is None
    assert row.status == CAStatusEnum.ACTIVE
    assert row.key_encrypted_pem is None
    assert row.serial_number == format(cert.serial_number, "x")
    assert row.subject_cn == cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert row.subject_json["CN"] == row.subject_cn
    assert row.cert_pem.strip() == (cer / "root-ca.pem").read_bytes().decode().strip()

    audit = db_session.scalars(select(AuditLog).where(AuditLog.action == "CA_IMPORT_ROOT_CERT")).one()
    assert audit.actor_id == "cli"
    assert audit.target_id == out["ca_id"]


def test_import_root_cert_duplicate_fails(capsys, db_session, SessionLocal, cer):
    first = _import_root(capsys, SessionLocal, cer)
    code, out, err = run(
        capsys,
        ["ca", "import-root-cert", "--name", "Again", "--cert", str(cer / "root-ca.pem")],
        session_factory=SessionLocal,
    )
    assert code == 1
    assert out == ""
    assert err.strip() == f"error: certificate already imported as {first['ca_id']}"
    assert len(db_session.scalars(select(CertificateAuthority)).all()) == 1


def test_import_root_cert_rejects_non_ca(capsys, db_session, SessionLocal, tmp_path):
    leaf, _key = self_signed("leaf", ca=False)
    path = tmp_path / "leaf.pem"
    path.write_bytes(cert_pem(leaf))
    code, _out, err = run(
        capsys, ["ca", "import-root-cert", "--name", "x", "--cert", str(path)], session_factory=SessionLocal
    )
    assert code == 1
    assert "not a CA" in err
    assert db_session.scalars(select(CertificateAuthority)).all() == []


def test_import_root_cert_rejects_not_self_signed(capsys, db_session, SessionLocal, cer):
    code, _out, err = run(
        capsys,
        ["ca", "import-root-cert", "--name", "x", "--cert", str(cer / "issuing-ca.pem")],
        session_factory=SessionLocal,
    )
    assert code == 1
    assert "not self-signed" in err
    assert db_session.scalars(select(CertificateAuthority)).all() == []


def test_import_root_cert_rejects_two_certificates(capsys, SessionLocal, cer):
    code, _out, err = run(
        capsys,
        ["ca", "import-root-cert", "--name", "x", "--cert", str(cer / "chain.pem")],
        session_factory=SessionLocal,
    )
    assert code == 1
    assert err.strip() == "error: expected exactly one certificate"


def test_import_root_cert_rejects_missing_file(capsys, SessionLocal, tmp_path):
    code, _out, err = run(
        capsys,
        ["ca", "import-root-cert", "--name", "x", "--cert", str(tmp_path / "nope.pem")],
        session_factory=SessionLocal,
    )
    assert code == 1
    assert err.strip() == "error: expected exactly one certificate"


# --- ca import --------------------------------------------------------------------------


def test_ca_import_happy_path(capsys, monkeypatch, db_session, SessionLocal, ring, cer, tmp_path):
    root = _import_root(capsys, SessionLocal, cer)
    before = _files(tmp_path)
    code, out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer)
    assert code == 0, err
    result = json.loads(out)
    assert set(result) == {"ca_id", "name", "sha256_fingerprint", "parent_ca_id"}
    assert result["parent_ca_id"] == root["ca_id"]

    db_session.expire_all()
    row = db_session.get(CertificateAuthority, result["ca_id"])
    assert row is not None
    assert row.source_type == CASourceTypeEnum.INTERMEDIATE
    assert row.parent_ca_id == root["ca_id"]
    assert row.status == CAStatusEnum.ACTIVE
    assert row.key_encrypted_pem is not None and row.key_encrypted_pem.startswith("labca:v1:")
    assert row.key_algorithm == "ECDSA"

    original = serialization.load_pem_private_key((cer / "issuing-ca.key.pem").read_bytes(), password=None)
    plain = ring.unseal(row.key_encrypted_pem, keystore.aad_for(keystore.CA_KEY_TABLE, row.id, keystore.CA_KEY_COLUMN))
    restored = serialization.load_pem_private_key(plain, password=None)
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    assert restored.public_key().public_bytes(serialization.Encoding.DER, spki) == original.public_key().public_bytes(
        serialization.Encoding.DER, spki
    )

    assert _files(tmp_path) == before
    assert "PRIVATE KEY" not in out + err
    assert "labca:v1:" not in out + err

    audit = db_session.scalars(select(AuditLog).where(AuditLog.action == "CA_IMPORT")).one()
    assert audit.actor_id == "cli"
    assert audit.details_json["parent_ca_id"] == root["ca_id"]
    assert "PRIVATE KEY" not in json.dumps(audit.details_json)
    assert "labca:v1:" not in json.dumps(audit.details_json)


def test_deploy_path_resolves_issuer_and_trust_bundle(capsys, monkeypatch, db_session, SessionLocal, cer):
    ring = keystore.get_keyring()
    _import_root(capsys, SessionLocal, cer)
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer)
    assert code == 0, err
    monkeypatch.setenv("WORKLOAD_ISSUER_CA_NAME", ISSUING_NAME)
    get_settings.cache_clear()
    issuer = pki_service.resolve_workload_issuer(db_session, get_settings())
    assert issuer is not None and issuer.name == ISSUING_NAME
    bundle = pki_service.trust_bundle_certificates(db_session)
    root_cert = x509.load_pem_x509_certificate((cer / "root-ca.pem").read_bytes())
    assert [pki_service.sha256_fingerprint_hex(c) for c in bundle] == [pki_service.sha256_fingerprint_hex(root_cert)]


def test_ca_import_requires_imported_root(capsys, monkeypatch, db_session, SessionLocal, ring, cer):
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer)
    assert code == 1
    assert err.strip() == "error: issuer is not imported; run 'ca import-root-cert' first"
    assert db_session.scalars(select(CertificateAuthority)).all() == []


def test_ca_import_wrong_key(capsys, monkeypatch, db_session, SessionLocal, ring, cer):
    _import_root(capsys, SessionLocal, cer)
    other = ec.generate_private_key(ec.SECP256R1())
    code, out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, key=key_pem(other))
    assert code == 1
    assert err.strip() == "error: key does not match certificate"
    assert "PRIVATE KEY" not in out + err
    assert len(db_session.scalars(select(CertificateAuthority)).all()) == 1


def test_ca_import_encrypted_key(capsys, monkeypatch, SessionLocal, ring, cer):
    _import_root(capsys, SessionLocal, cer)
    original = serialization.load_pem_private_key((cer / "issuing-ca.key.pem").read_bytes(), password=None)
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, key=key_pem(original, b"pw"))
    assert code == 1
    assert err.strip() == "error: encrypted keys are not supported; decrypt into the pipe"


def test_ca_import_garbage_key(capsys, monkeypatch, SessionLocal, ring, cer):
    _import_root(capsys, SessionLocal, cer)
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, key=b"not a key")
    assert code == 1
    assert "PRIVATE KEY" not in err


def test_ca_import_empty_stdin(capsys, monkeypatch, SessionLocal, ring, cer):
    _import_root(capsys, SessionLocal, cer)
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, key=b"")
    assert code == 1
    assert err.startswith("error:")


def test_ca_import_oversized_stdin(capsys, monkeypatch, SessionLocal, ring, cer):
    _import_root(capsys, SessionLocal, cer)
    big = (cer / "issuing-ca.key.pem").read_bytes() + b"#" * (64 * 1024)
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, key=big)
    assert code == 1
    assert "64 KiB" in err


@pytest.mark.parametrize(
    "key",
    [
        ed25519.Ed25519PrivateKey.generate(),
        ec.generate_private_key(ec.SECP521R1()),
        rsa.generate_private_key(65537, 1024),
    ],
    ids=["ed25519", "p521", "rsa1024"],
)
def test_ca_import_unsupported_key_types(capsys, monkeypatch, SessionLocal, ring, cer, key):
    _import_root(capsys, SessionLocal, cer)
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, key=key_pem(key))
    assert code == 1
    assert "P-256" in err


def test_ca_import_rejects_non_ca_certificate(capsys, monkeypatch, db_session, SessionLocal, ring, cer, tmp_path):
    _import_root(capsys, SessionLocal, cer)
    leaf, leaf_key = self_signed("leaf", ca=False)
    leaf_path = tmp_path / "leaf.pem"
    leaf_path.write_bytes(cert_pem(leaf))
    set_stdin(monkeypatch, key_pem(leaf_key))
    code, _out, err = run(
        capsys,
        ["ca", "import", "--name", "x", "--cert", str(leaf_path), "--chain", str(cer / "chain.pem"), "--key-stdin"],
        session_factory=SessionLocal,
        keyring=ring,
    )
    assert code == 1
    assert "not a CA" in err


def test_ca_import_chain_first_not_issuer(capsys, monkeypatch, SessionLocal, ring, cer, tmp_path):
    _import_root(capsys, SessionLocal, cer)
    stranger, _key = self_signed("stranger", ca=True)
    chain = tmp_path / "bad-chain.pem"
    chain.write_bytes(cert_pem(stranger))
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, chain=chain)
    assert code == 1
    assert err.strip() == "error: certificate is not issued by the first chain certificate"


def test_ca_import_chain_without_issuer(capsys, monkeypatch, SessionLocal, ring, cer, tmp_path):
    _import_root(capsys, SessionLocal, cer)
    chain = tmp_path / "self-only.pem"
    chain.write_bytes((cer / "issuing-ca.pem").read_bytes())
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, chain=chain)
    assert code == 1
    assert "issuer" in err


def test_ca_import_unreadable_chain(capsys, monkeypatch, SessionLocal, ring, cer, tmp_path):
    _import_root(capsys, SessionLocal, cer)
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer, chain=tmp_path / "missing.pem")
    assert code == 1
    assert err.startswith("error:")


def test_ca_import_duplicate(capsys, monkeypatch, db_session, SessionLocal, ring, cer):
    _import_root(capsys, SessionLocal, cer)
    code, out, _err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer)
    assert code == 0
    first_id = json.loads(out)["ca_id"]
    code, _out, err = _import_issuing(capsys, monkeypatch, SessionLocal, ring, cer)
    assert code == 1
    assert err.strip() == f"error: certificate already imported as {first_id}"
    assert len(db_session.scalars(select(CertificateAuthority)).all()) == 2


def test_ca_import_without_active_kek_reports_error(capsys, monkeypatch, db_session, SessionLocal, cer):
    _import_root(capsys, SessionLocal, cer)
    code, out, err = _import_issuing(capsys, monkeypatch, SessionLocal, KeyRing({}), cer)
    assert code == 1
    assert "could not seal the key" in err
    assert "PRIVATE KEY" not in out + err
    assert len(db_session.scalars(select(CertificateAuthority)).all()) == 1


def test_ca_import_requires_key_stdin_flag(cer):
    with pytest.raises(SystemExit) as info:
        cli.main(
            [
                "ca",
                "import",
                "--name",
                "x",
                "--cert",
                str(cer / "issuing-ca.pem"),
                "--chain",
                str(cer / "chain.pem"),
            ]
        )
    assert info.value.code == 2


def test_stdin_is_not_used_when_key_flag_missing(cer, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"unused")))
    with pytest.raises(SystemExit):
        cli.main(["ca", "import", "--name", "x", "--cert", "a", "--chain", "b"])
    assert sys.stdin.buffer.read() == b"unused"
