"""Offline PKI ceremony tool for the LabCA root and workload issuing CAs.

Subcommands:
    init              create the root CA, an empty root CRL, and the issuing CA
    renew-root-crl    issue the next root CRL, carrying earlier entries forward
    new-issuing-ca    replace the issuing CA under an existing root

Exit codes: 0 success, 1 runtime failure, 2 usage or validation error.
Messages on stderr never contain passphrases or key material.
"""

import argparse
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT_CN = "LabCA Offline Root CA 2026"
ISSUING_CN_DEFAULT = "LabCA Workload Issuing CA 1"
ORG = "LabCA"
ROOT_VALIDITY = timedelta(days=3650)  # 10 years
ISSUING_VALIDITY = timedelta(days=1095)  # 3 years
ROOT_CRL_VALIDITY = timedelta(days=365)
BACKDATE = timedelta(minutes=5)  # not_before and CRL last_update = now - BACKDATE

REASONS: Dict[str, x509.ReasonFlags] = {
    "keyCompromise": x509.ReasonFlags.key_compromise,
    "cACompromise": x509.ReasonFlags.ca_compromise,
    "superseded": x509.ReasonFlags.superseded,
    "cessationOfOperation": x509.ReasonFlags.cessation_of_operation,
    "unspecified": x509.ReasonFlags.unspecified,
}


class CeremonyError(Exception):
    """A reportable failure. code 2 is usage or validation, code 1 is runtime."""

    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- helpers


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        ]
    )


def _key_usage_ca() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _fingerprint(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def _fingerprint_lines(root: x509.Certificate, issuing: x509.Certificate) -> str:
    return (
        f"root-ca.pem sha256 Fingerprint={_fingerprint(root)}\n"
        f"issuing-ca.pem sha256 Fingerprint={_fingerprint(issuing)}\n"
    )


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _validate_cdp(url: str) -> None:
    try:
        parts = urlsplit(url)
    except ValueError:
        raise CeremonyError("--issuing-cdp is not a valid URL", 2) from None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise CeremonyError("--issuing-cdp must be an http or https URL with a host", 2)


def _refuse_existing(files: Dict[Path, bytes]) -> None:
    for path in files:
        if os.path.lexists(path):
            raise CeremonyError(f"refusing to overwrite existing file: {path}", 1)


def _write_new_files(files: Dict[Path, bytes]) -> List[Path]:
    """Write every file with mode 0600 and O_EXCL; write nothing if any exists."""
    _refuse_existing(files)
    written: List[Path] = []
    for path, data in files.items():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise CeremonyError(f"refusing to overwrite existing file: {path}", 1) from None
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(path, 0o600)
        written.append(path)
    return written


def _ensure_dir(path: Path) -> None:
    if path.exists():
        if not path.is_dir():
            raise CeremonyError(f"not a directory: {path}", 2)
        return
    path.mkdir(mode=0o700, parents=True)
    os.chmod(path, 0o700)


def _private_pem(key: ec.EllipticCurvePrivateKey, password: Optional[bytes]) -> bytes:
    enc: serialization.KeySerializationEncryption
    if password is None:
        enc = serialization.NoEncryption()
    else:
        enc = serialization.BestAvailableEncryption(password)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def _ski_ext(cert: x509.Certificate) -> x509.SubjectKeyIdentifier:
    return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value


# ---------------------------------------------------------------- builders


def build_root(now: datetime) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP384R1())
    name = _name(ROOT_CN)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    not_before = now - BACKDATE
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + ROOT_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage_ca(), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=ski.digest, authority_cert_issuer=None, authority_cert_serial_number=None
            ),
            critical=False,
        )
        .sign(key, hashes.SHA384())
    )
    return key, cert


def build_issuing(
    root_key: ec.EllipticCurvePrivateKey,
    root_cert: x509.Certificate,
    cn: str,
    cdp: str,
    now: datetime,
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    not_before = now - BACKDATE
    not_after = not_before + ISSUING_VALIDITY
    if not_after > root_cert.not_valid_after_utc:
        raise CeremonyError("issuing CA would outlive the root CA certificate", 2)
    key = ec.generate_private_key(ec.SECP256R1())
    root_aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(_ski_ext(root_cert))
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage_ca(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(root_aki, critical=False)
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(cdp)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA384())
    )
    return key, cert


def build_crl(
    root_key: ec.EllipticCurvePrivateKey,
    root_cert: x509.Certificate,
    number: int,
    now: datetime,
    validity: timedelta,
    entries: Sequence[x509.RevokedCertificate],
) -> x509.CertificateRevocationList:
    last_update = now - BACKDATE
    root_aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(_ski_ext(root_cert))
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)
        .last_update(last_update)
        .next_update(last_update + validity)
        .add_extension(x509.CRLNumber(number), critical=False)
        .add_extension(root_aki, critical=False)
    )
    for entry in entries:
        builder = builder.add_revoked_certificate(entry)
    return builder.sign(root_key, hashes.SHA384())


# ---------------------------------------------------------------- loading


def _read(path: Path, what: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CeremonyError(f"cannot read {what}: {exc.strerror}", 1) from None


def load_root(
    cert_path: Path, key_path: Path, passphrase_path: Path
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    try:
        cert = x509.load_pem_x509_certificate(_read(cert_path, "root certificate"))
    except ValueError:
        raise CeremonyError("root certificate is not a valid PEM certificate", 1) from None
    passphrase = _read(passphrase_path, "passphrase file").strip()
    key_data = _read(key_path, "root key")
    try:
        loaded = serialization.load_pem_private_key(key_data, password=passphrase)
    except (ValueError, TypeError):
        raise CeremonyError("cannot decrypt the root key with the given passphrase", 1) from None
    if not isinstance(loaded, ec.EllipticCurvePrivateKey):
        raise CeremonyError("root key is not an EC key", 1)
    der = serialization.Encoding.DER
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    if loaded.public_key().public_bytes(der, spki) != cert.public_key().public_bytes(der, spki):
        raise CeremonyError("root key does not match the root certificate", 1)
    return loaded, cert


def _load_crl(path: Path) -> x509.CertificateRevocationList:
    data = _read(path, "previous CRL")
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_crl(data)
        return x509.load_der_x509_crl(data)
    except ValueError:
        raise CeremonyError("previous CRL cannot be parsed", 1) from None


# ---------------------------------------------------------------- init


def _has_git(path: Path) -> bool:
    return any(os.path.lexists(candidate / ".git") for candidate in [path, *path.parents])


def _is_inside(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def _check_root_key_dir(out_dir: Path, key_dir: Path) -> None:
    if _is_inside(key_dir, out_dir) or _is_inside(out_dir, key_dir):
        raise CeremonyError("root key dir must be separate from --out (not equal, inside, or containing it)", 2)
    if _has_git(key_dir):
        raise CeremonyError("root key dir is inside a git working tree; choose another location", 2)


def cmd_init(args: argparse.Namespace) -> int:
    _validate_cdp(args.issuing_cdp)
    out_dir = Path(args.out).expanduser().resolve()
    key_dir: Optional[Path] = None
    if args.mode == "test":
        if args.root_key_dir is not None:
            raise CeremonyError("--root-key-dir is not allowed in test mode", 2)
    else:
        raw = Path(args.root_key_dir) if args.root_key_dir else Path.home() / "labca-offline-root"
        key_dir = raw.expanduser().resolve()
        _check_root_key_dir(out_dir, key_dir)

    now = _now()
    root_key, root_cert = build_root(now)
    issuing_key, issuing_cert = build_issuing(root_key, root_cert, args.issuing_cn, args.issuing_cdp, now)
    crl = build_crl(root_key, root_cert, 1, now, ROOT_CRL_VALIDITY, [])
    passphrase = secrets.token_urlsafe(32)

    root_pem = _cert_pem(root_cert)
    issuing_pem = _cert_pem(issuing_cert)
    fingerprints = _fingerprint_lines(root_cert, issuing_cert)
    secret_dir = key_dir if key_dir is not None else out_dir
    files: Dict[Path, bytes] = {
        out_dir / "root-ca.pem": root_pem,
        out_dir / "root-crl.der": crl.public_bytes(serialization.Encoding.DER),
        out_dir / "root-crl.pem": crl.public_bytes(serialization.Encoding.PEM),
        out_dir / "issuing-ca.pem": issuing_pem,
        out_dir / "chain.pem": issuing_pem + root_pem,
        out_dir / "issuing-ca.key.pem": _private_pem(issuing_key, None),
        out_dir / "fingerprints.txt": fingerprints.encode(),
        secret_dir / "root-ca.key.enc": _private_pem(root_key, passphrase.encode()),
        secret_dir / "root-passphrase.txt": (passphrase + "\n").encode(),
    }
    _refuse_existing(files)

    _ensure_dir(out_dir)
    if key_dir is not None:
        _ensure_dir(key_dir)
    for path in _write_new_files(files):
        print(path)
    print(fingerprints, end="")
    if key_dir is not None:
        print(f"encrypted root key and passphrase written to {key_dir}; move them to offline storage")
    return 0


# ---------------------------------------------------------------- renew-root-crl


def _parse_revoke(spec: str) -> Tuple[int, x509.ReasonFlags]:
    serial_text, sep, reason_text = spec.partition(":")
    if not sep or reason_text not in REASONS:
        raise CeremonyError(f"--revoke must be SERIAL_HEX:REASON with REASON in {sorted(REASONS)}", 2)
    try:
        serial = int(serial_text, 16)
    except ValueError:
        raise CeremonyError("--revoke serial is not valid hex", 2) from None
    if serial <= 0:
        raise CeremonyError("--revoke serial must be positive", 2)
    return serial, REASONS[reason_text]


def cmd_renew_root_crl(args: argparse.Namespace) -> int:
    if args.days is not None and args.days <= 0:
        raise CeremonyError("--days must be positive", 2)
    revokes = [_parse_revoke(spec) for spec in args.revoke]
    root_key, root_cert = load_root(Path(args.root_cert), Path(args.root_key), Path(args.passphrase_file))
    previous = _load_crl(Path(args.previous_crl))
    if previous.issuer != root_cert.subject or not previous.is_signature_valid(root_key.public_key()):
        raise CeremonyError("previous CRL was not issued by this root", 1)
    try:
        prev_number = previous.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        raise CeremonyError("previous CRL has no CRL number", 1) from None

    now = _now()
    entries: List[x509.RevokedCertificate] = list(previous)
    seen = {entry.serial_number for entry in entries}
    for serial, reason in revokes:
        if serial in seen:
            raise CeremonyError(f"serial {serial:x} is already revoked", 2)
        seen.add(serial)
        entries.append(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now)
            .add_extension(x509.CRLReason(reason), critical=False)
            .build()
        )
    validity = timedelta(days=args.days) if args.days is not None else ROOT_CRL_VALIDITY
    crl = build_crl(root_key, root_cert, prev_number + 1, now, validity, entries)

    out_dir = Path(args.out).expanduser().resolve()
    files = {
        out_dir / "root-crl.der": crl.public_bytes(serialization.Encoding.DER),
        out_dir / "root-crl.pem": crl.public_bytes(serialization.Encoding.PEM),
    }
    _refuse_existing(files)
    _ensure_dir(out_dir)
    for path in _write_new_files(files):
        print(path)
    print(f"crl number {prev_number + 1}, {len(entries)} entries")
    return 0


# ---------------------------------------------------------------- new-issuing-ca


def cmd_new_issuing_ca(args: argparse.Namespace) -> int:
    _validate_cdp(args.issuing_cdp)
    root_key, root_cert = load_root(Path(args.root_cert), Path(args.root_key), Path(args.passphrase_file))
    issuing_key, issuing_cert = build_issuing(root_key, root_cert, args.issuing_cn, args.issuing_cdp, _now())
    root_pem = _cert_pem(root_cert)
    issuing_pem = _cert_pem(issuing_cert)
    fingerprints = _fingerprint_lines(root_cert, issuing_cert)

    out_dir = Path(args.out).expanduser().resolve()
    files = {
        out_dir / "issuing-ca.pem": issuing_pem,
        out_dir / "issuing-ca.key.pem": _private_pem(issuing_key, None),
        out_dir / "chain.pem": issuing_pem + root_pem,
        out_dir / "fingerprints.txt": fingerprints.encode(),
    }
    _refuse_existing(files)
    _ensure_dir(out_dir)
    for path in _write_new_files(files):
        print(path)
    print(fingerprints, end="")
    return 0


# ---------------------------------------------------------------- cli


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ceremony", description="LabCA offline PKI ceremony tool")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create root CA, empty root CRL, and issuing CA")
    init.add_argument("--mode", choices=["prod", "test"], required=True)
    init.add_argument("--out", required=True)
    init.add_argument("--issuing-cdp", required=True)
    init.add_argument("--issuing-cn", default=ISSUING_CN_DEFAULT)
    init.add_argument("--root-key-dir", default=None)
    init.set_defaults(func=cmd_init)

    renew = sub.add_parser("renew-root-crl", help="issue the next root CRL")
    renew.add_argument("--root-cert", required=True)
    renew.add_argument("--root-key", required=True)
    renew.add_argument("--passphrase-file", required=True)
    renew.add_argument("--previous-crl", required=True)
    renew.add_argument("--out", required=True)
    renew.add_argument("--revoke", action="append", default=[], metavar="SERIAL_HEX:REASON")
    renew.add_argument("--days", type=int, default=None)
    renew.set_defaults(func=cmd_renew_root_crl)

    new = sub.add_parser("new-issuing-ca", help="replace the issuing CA under the existing root")
    new.add_argument("--root-cert", required=True)
    new.add_argument("--root-key", required=True)
    new.add_argument("--passphrase-file", required=True)
    new.add_argument("--out", required=True)
    new.add_argument("--issuing-cdp", required=True)
    new.add_argument("--issuing-cn", required=True)
    new.set_defaults(func=cmd_new_issuing_ca)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        return int(args.func(args))
    except CeremonyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except OSError as exc:
        print(f"error: {exc.strerror or 'file system error'}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
