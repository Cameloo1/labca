"""Shared helpers for the operations CLI tests (real ceremony output, certificate factories, CLI runner)."""

from __future__ import annotations

import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import cli
from pki.ceremony import ceremony

CDP = "https://labca.example.test/pki/root/crl.der"
ROOT_NAME = "LabCA Offline Root CA 2026"
ISSUING_NAME = "LabCA Workload Issuing CA 1"


def make_ceremony(out: Path) -> Path:
    """Run the offline ceremony in test mode and return its output directory."""
    assert ceremony.main(["init", "--mode", "test", "--out", str(out), "--issuing-cdp", CDP]) == 0
    return out


def self_signed(name: str, *, ca: bool, key: Optional[ec.EllipticCurvePrivateKey] = None):
    """Return (certificate, private key) for a throwaway self-signed certificate."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key: Any, password: Optional[bytes] = None) -> bytes:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


def set_stdin(monkeypatch, data: bytes) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))


def run(capsys, argv: list[str], **kwargs) -> tuple[int, str, str]:
    """Run cli.main and return (exit code, stdout, stderr)."""
    capsys.readouterr()
    code = cli.main(argv, **kwargs)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_json(capsys, argv: list[str], **kwargs) -> tuple[int, dict]:
    code, out, _err = run(capsys, argv, **kwargs)
    return code, json.loads(out) if out.strip() else {}
