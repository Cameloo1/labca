"""Operator command line: kek, ca, backup, verify-db, prune, and crl commands (``python -m app.cli --help``)."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import create_engine, delete, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    ActorType,
    AuditStatus,
    CASourceTypeEnum,
    CAStatusEnum,
    Certificate,
    CertificateAuthority,
    NotificationLog,
)
from app.services import ca_service, crl_service, keystore, pki_service
from app.services.audit_service import log_action
from app.services.persistence import create_certificate_authority

_MAX_KEY_BYTES = 64 * 1024

# (table, column, ORM class); the column names match keystore.SEALED_COLUMNS.
_SEALED_MODELS: Tuple[Tuple[str, str, Any], ...] = (
    (keystore.CA_KEY_TABLE, keystore.CA_KEY_COLUMN, CertificateAuthority),
    (keystore.CERT_KEY_TABLE, keystore.CERT_KEY_COLUMN, Certificate),
)


def _emit(obj: Dict[str, Any]) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="LabCA operator commands.")
    groups = parser.add_subparsers(dest="group", required=True)
    kek = groups.add_parser("kek", help="Key encryption key management.")
    actions = kek.add_subparsers(dest="action", required=True)
    actions.add_parser("status", help="Show loaded KEKs and how many records each one protects.")
    rewrap = actions.add_parser("rewrap", help="Re-wrap every stored key under another KEK.")
    rewrap.add_argument("--to", required=True, dest="to_kek_id", help="Target KEK id.")
    rewrap.add_argument("--dry-run", action="store_true", help="Compute the result without saving it.")

    ca = groups.add_parser("ca", help="Import certificate authorities.")
    ca_actions = ca.add_subparsers(dest="action", required=True)
    import_root = ca_actions.add_parser("import-root-cert", help="Import a root certificate (no key).")
    import_root.add_argument("--name", required=True, help="Display name for the CA.")
    import_root.add_argument("--cert", required=True, help="Path of a PEM file holding one certificate.")
    import_ca = ca_actions.add_parser(
        "import",
        help="Import an issuing CA; the private key PEM is read from stdin and sealed immediately.",
    )
    import_ca.add_argument("--name", required=True, help="Display name for the CA.")
    import_ca.add_argument("--cert", required=True, help="Path of the PEM file with the CA certificate.")
    import_ca.add_argument("--chain", required=True, help="Path of a PEM file with the issuer chain.")
    import_ca.add_argument("--key-stdin", required=True, action="store_true", help="Read the key PEM from stdin.")

    backup = groups.add_parser(
        "backup",
        help="Online SQLite backup. The backup holds sealed keys only, never plaintext key material.",
        description="Online SQLite backup. The backup holds sealed keys only, never plaintext key material.",
    )
    backup.add_argument("--out-dir", required=True, help="Directory for backups (created with mode 0700).")
    backup.add_argument("--keep", required=True, type=int, help="Number of newest backups to keep (at least 1).")

    verify = groups.add_parser(
        "verify-db", help="Check database integrity and that each CA key matches its certificate."
    )
    verify.add_argument("--db", required=True, help="Path of the SQLite file to open read-only.")

    prune = groups.add_parser("prune", help="Remove old expired workload certificates.")
    prune.add_argument("--expired-workload-older-than-days", required=True, type=int, dest="days")
    prune.add_argument("--dry-run", action="store_true", help="Count without deleting.")

    crl = groups.add_parser("crl", help="CRL operations.")
    crl_actions = crl.add_subparsers(dest="action", required=True)
    regenerate = crl_actions.add_parser("regenerate", help="Force a new CRL for one CA.")
    regenerate.add_argument("--ca-name", required=True, help="Name of the ACTIVE CA that LabCA holds a key for.")
    return parser


def _sealed_rows(db: Session) -> List[Tuple[str, str, Any, str]]:
    """Return (table, column, row, value) for every non-null sealed value."""
    found: List[Tuple[str, str, Any, str]] = []
    for table, column, model in _SEALED_MODELS:
        for row in db.scalars(select(model)).all():
            value = getattr(row, column)
            if value is not None:
                found.append((table, column, row, value))
    return found


def _cmd_status(db: Session, keyring: keystore.KeyRing) -> int:
    totals: Counter[str] = Counter()
    by_column: Dict[str, Dict[str, int]] = {f"{table}.{column}": {} for table, column in keystore.SEALED_COLUMNS}
    legacy = 0
    malformed = 0
    for table, column, _row, value in _sealed_rows(db):
        try:
            kek_id = keystore.kek_id_of(value)
        except keystore.LegacyFormatError:
            legacy += 1
            continue
        except keystore.MalformedTokenError:
            malformed += 1
            continue
        totals[kek_id] += 1
        column_counts = by_column[f"{table}.{column}"]
        column_counts[kek_id] = column_counts.get(kek_id, 0) + 1
    _emit(
        {
            "active_kek_id": keyring.active_kek_id,
            "loaded_kek_ids": keyring.kek_ids,
            "records": dict(totals),
            "by_column": by_column,
            "legacy": legacy,
            "malformed": malformed,
        }
    )
    return 0


def _cmd_rewrap(db: Session, keyring: keystore.KeyRing, to_kek_id: str, dry_run: bool) -> int:
    if not keyring.has(to_kek_id):
        _error(f"KEK '{to_kek_id}' is not loaded")
        return 2

    rows = _sealed_rows(db)
    if any(value.startswith(keystore.LEGACY_PREFIX) for _t, _c, _r, value in rows):
        _error("legacy enc:: values present; run 'alembic upgrade head' first")
        return 1

    rewrapped = 0
    already_current = 0
    by_source: Counter[str] = Counter()
    for table, column, row, value in rows:
        row_id = row.id
        try:
            old_id = keystore.kek_id_of(value)
            if old_id == to_kek_id:
                keyring.rewrap(value, keystore.aad_for(table, row_id, column), to_kek_id)
                already_current += 1
                continue
            new_value = keyring.rewrap(value, keystore.aad_for(table, row_id, column), to_kek_id)
        except keystore.KeystoreError as exc:
            db.rollback()
            _error(f"rewrap failed for {table} {row_id}: {type(exc).__name__}")
            return 1
        setattr(row, column, new_value)
        rewrapped += 1
        by_source[old_id] += 1

    result = {
        "to_kek_id": to_kek_id,
        "dry_run": dry_run,
        "rewrapped": rewrapped,
        "already_current": already_current,
        "by_source_kek": dict(by_source),
    }
    if dry_run:
        db.rollback()
    else:
        # log_action commits, so the key updates and the audit row land in one transaction.
        log_action(
            db,
            actor_type=ActorType.SYSTEM,
            actor_id="cli",
            action="KEK_REWRAP",
            target_type="KEK",
            target_id=to_kek_id,
            status=AuditStatus.SUCCESS,
            details={
                "to_kek_id": to_kek_id,
                "rewrapped": rewrapped,
                "already_current": already_current,
                "by_source_kek": dict(by_source),
            },
        )
    _emit(result)
    return 0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_certificates(path: str) -> Optional[List[x509.Certificate]]:
    """Return the PEM certificates in a file, or None when it cannot be read or parsed."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        return list(x509.load_pem_x509_certificates(data))
    except (OSError, ValueError):
        return None


def _is_ca_certificate(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _find_existing(db: Session, cert: x509.Certificate) -> Optional[CertificateAuthority]:
    """Return the CA with the same SHA-256 fingerprint or serial number, if any."""
    fingerprint = pki_service.sha256_fingerprint_hex(cert)
    serial = format(cert.serial_number, "x")
    for existing in db.scalars(select(CertificateAuthority)).all():
        if existing.serial_number == serial:
            return existing
        try:
            if pki_service.sha256_fingerprint_hex(pki_service.load_ca_certificate(existing)) == fingerprint:
                return existing
        except ValueError:
            continue
    return None


def _key_label_and_size(public_key: Any) -> Tuple[str, int]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.key_size
    return type(public_key).__name__, int(getattr(public_key, "key_size", 0))


def _spki(public_key: Any) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _ca_record_fields(name: str, cert: x509.Certificate, ca_id: str, label: str, size: int) -> Dict[str, Any]:
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    cn_values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "id": ca_id,
        "name": name,
        "subject_cn": str(cn_values[0].value) if cn_values else "",
        "subject_json": ca_service._subject_json_from_cert(cert, basic.path_length),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "key_algorithm": label,
        "key_size": size,
        "status": CAStatusEnum.ACTIVE,
        "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
    }


def _cmd_import_root_cert(db: Session, name: str, cert_path: str) -> int:
    certs = _read_certificates(cert_path)
    if certs is None or len(certs) != 1:
        _error("expected exactly one certificate")
        return 1
    cert = certs[0]
    if not _is_ca_certificate(cert):
        _error("certificate is not a CA certificate")
        return 1
    if not pki_service.is_self_signed(cert):
        _error("certificate is not self-signed")
        return 1
    existing = _find_existing(db, cert)
    if existing is not None:
        _error(f"certificate already imported as {existing.id}")
        return 1
    ca_id = str(uuid.uuid4())
    label, size = _key_label_and_size(cert.public_key())
    fields = _ca_record_fields(name, cert, ca_id, label, size)
    create_certificate_authority(
        db,
        {
            **fields,
            "source_type": CASourceTypeEnum.EXTERNAL_IMPORTED,
            "parent_ca_id": None,
            "key_encrypted_pem": None,
        },
    )
    fingerprint = pki_service.sha256_fingerprint_hex(cert)
    log_action(
        db,
        actor_type=ActorType.SYSTEM,
        actor_id="cli",
        action="CA_IMPORT_ROOT_CERT",
        target_type="CA",
        target_id=ca_id,
        status=AuditStatus.SUCCESS,
        details={"name": name, "sha256_fingerprint": fingerprint},
    )
    _emit({"ca_id": ca_id, "name": name, "sha256_fingerprint": fingerprint})
    return 0


def _cmd_import_ca(db: Session, keyring: keystore.KeyRing, name: str, cert_path: str, chain_path: str) -> int:
    data = sys.stdin.buffer.read(_MAX_KEY_BYTES + 1)
    if not data:
        _error("no key was provided on stdin")
        return 1
    if len(data) > _MAX_KEY_BYTES:
        _error("key input is larger than 64 KiB")
        return 1
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        _error("encrypted keys are not supported; decrypt into the pipe")
        return 1
    except (ValueError, UnsupportedAlgorithm):
        _error("stdin does not hold a supported unencrypted PEM private key")
        return 1
    finally:
        del data
    supported = (isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048) or (
        isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name in ("secp256r1", "secp384r1")
    )
    if not supported:
        _error("key must be ECDSA P-256, ECDSA P-384, or RSA of at least 2048 bits")
        return 1

    certs = _read_certificates(cert_path)
    if certs is None or len(certs) != 1:
        _error("expected exactly one certificate")
        return 1
    cert = certs[0]
    if not _is_ca_certificate(cert):
        _error("certificate is not a CA certificate")
        return 1
    if _spki(key.public_key()) != _spki(cert.public_key()):
        _error("key does not match certificate")
        return 1

    chain = _read_certificates(chain_path)
    if chain is None:
        _error("chain file could not be read")
        return 1
    remaining = [item for item in chain if item != cert]
    if not remaining:
        _error("chain does not contain an issuer certificate")
        return 1
    issuer_cert = remaining[0]
    try:
        cert.verify_directly_issued_by(issuer_cert)
    except (ValueError, TypeError, InvalidSignature):
        _error("certificate is not issued by the first chain certificate")
        return 1

    existing = _find_existing(db, cert)
    if existing is not None:
        _error(f"certificate already imported as {existing.id}")
        return 1
    issuer_row = _find_existing(db, issuer_cert)
    if issuer_row is None or pki_service.sha256_fingerprint_hex(
        pki_service.load_ca_certificate(issuer_row)
    ) != pki_service.sha256_fingerprint_hex(issuer_cert):
        _error("issuer is not imported; run 'ca import-root-cert' first")
        return 1

    ca_id = str(uuid.uuid4())
    pem_bytes = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    try:
        sealed = keyring.seal(pem_bytes, keystore.aad_for(keystore.CA_KEY_TABLE, ca_id, keystore.CA_KEY_COLUMN))
    except keystore.KeystoreError as exc:
        _error(f"could not seal the key: {type(exc).__name__}")
        return 1
    finally:
        del pem_bytes
    label, size = _key_label_and_size(key.public_key())
    del key

    create_certificate_authority(
        db,
        {
            **_ca_record_fields(name, cert, ca_id, label, size),
            "source_type": CASourceTypeEnum.INTERMEDIATE,
            "parent_ca_id": issuer_row.id,
            "key_encrypted_pem": sealed,
        },
    )
    fingerprint = pki_service.sha256_fingerprint_hex(cert)
    log_action(
        db,
        actor_type=ActorType.SYSTEM,
        actor_id="cli",
        action="CA_IMPORT",
        target_type="CA",
        target_id=ca_id,
        status=AuditStatus.SUCCESS,
        details={"name": name, "sha256_fingerprint": fingerprint, "parent_ca_id": issuer_row.id},
    )
    _emit({"ca_id": ca_id, "name": name, "sha256_fingerprint": fingerprint, "parent_ca_id": issuer_row.id})
    return 0


def _sqlite_file(database_url: str) -> Optional[str]:
    try:
        url = make_url(database_url)
    except ArgumentError:
        return None
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return None
    if url.database.startswith("file:"):
        return None
    return url.database


def _integrity_result(path: str) -> str:
    """Run PRAGMA integrity_check on a SQLite file; return 'ok' or the first line of the answer."""
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute("PRAGMA integrity_check").fetchall()  # fixed statement, no user input
    finally:
        conn.close()
    first = str(rows[0][0]) if rows else "no result"
    return "ok" if len(rows) == 1 and first == "ok" else first.splitlines()[0]


def _cmd_backup(out_dir: str, keep: int) -> int:
    source = _sqlite_file(get_settings().DATABASE_URL)
    if source is None:
        _error("backup supports file-based SQLite only")
        return 2
    if keep < 1:
        _error("--keep must be at least 1")
        return 2
    if not os.path.isfile(source):
        _error("database file not found")
        return 1

    target_dir = Path(out_dir)
    target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = _utcnow().strftime("%Y%m%dT%H%M%SZ")
    final = target_dir / f"labca-{stamp}.db"
    partial = target_dir / f"labca-{stamp}.db.partial"

    src = sqlite3.connect(f"{Path(source).resolve().as_uri()}?mode=ro", uri=True)
    try:
        dst = sqlite3.connect(partial)
        try:
            src.backup(dst)
        finally:
            dst.close()
    except sqlite3.Error as exc:
        partial.unlink(missing_ok=True)
        _error(f"backup failed: {type(exc).__name__}")
        return 1
    finally:
        src.close()

    if _integrity_result(str(partial)) != "ok":
        partial.unlink(missing_ok=True)
        _error("backup failed the integrity check")
        return 1
    os.chmod(partial, 0o600)
    os.replace(partial, final)

    names = sorted(item.name for item in target_dir.glob("labca-*.db") if item.is_file())
    pruned = names[:-keep] if len(names) > keep else []
    for stale in pruned:
        (target_dir / stale).unlink()
    _emit({"backup": str(final), "size_bytes": final.stat().st_size, "integrity": "ok", "pruned": pruned})
    return 0


def _ca_key_failure(keyring: keystore.KeyRing, ca: CertificateAuthority) -> Optional[str]:
    """Return the failure reason for one CA's sealed key, or None when it is sound."""
    try:
        raw = keyring.unseal(
            ca.key_encrypted_pem or "", keystore.aad_for(keystore.CA_KEY_TABLE, ca.id, keystore.CA_KEY_COLUMN)
        )
    except keystore.KeystoreError:
        return "unseal_failed"
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "key_unparseable"
    finally:
        del raw
    try:
        cert = pki_service.load_ca_certificate(ca)
    except ValueError:
        return "cert_unparseable"
    if _spki(key.public_key()) != _spki(cert.public_key()):
        return "key_mismatch"
    return None


def _cmd_verify_db(keyring: keystore.KeyRing, db_path: str) -> int:
    path = Path(db_path)
    if not path.is_file():
        _error("database file not found")
        return 1
    engine = create_engine(f"sqlite:///file:{path.resolve().as_posix()}?mode=ro&uri=true", connect_args={"uri": True})
    try:
        with engine.connect() as conn:
            rows = conn.exec_driver_sql("PRAGMA integrity_check").fetchall()  # fixed statement, no user input
            first = str(rows[0][0]) if rows else "no result"
            integrity = "ok" if len(rows) == 1 and first == "ok" else first.splitlines()[0]
        failures: List[Dict[str, str]] = []
        checked = 0
        if integrity == "ok":
            with Session(engine) as session:
                for ca in session.scalars(select(CertificateAuthority).order_by(CertificateAuthority.id)).all():
                    if not ca.key_encrypted_pem:
                        continue
                    checked += 1
                    reason = _ca_key_failure(keyring, ca)
                    if reason is not None:
                        failures.append({"ca_id": ca.id, "reason": reason})
    except SQLAlchemyError as exc:
        _error(f"database could not be read: {type(exc).__name__}")
        return 1
    finally:
        engine.dispose()
    _emit({"integrity": integrity, "cas_checked": checked, "failures": failures})
    return 0 if integrity == "ok" and not failures else 1


def _cmd_prune(db: Session, days: int, dry_run: bool) -> int:
    if days < 1:
        _error("--expired-workload-older-than-days must be at least 1")
        return 2
    retention = max(timedelta(days=days), timedelta(hours=get_settings().CRL_RETENTION_AFTER_EXPIRY_HOURS))
    cutoff = _utcnow() - retention
    rows = db.scalars(
        select(Certificate).where(Certificate.issued_to_spiffe_id.is_not(None), Certificate.not_after < cutoff)
    ).all()
    count = len(rows)
    if not dry_run:
        ids = [row.id for row in rows]
        if ids:
            db.execute(delete(NotificationLog).where(NotificationLog.certificate_id.in_(ids)))
        for row in rows:
            db.delete(row)
        _audit_prune(db, count)  # log_action commits the deletions and the audit row together
    _emit({"deleted": count, "dry_run": dry_run, "cutoff": _rfc3339(cutoff)})
    return 0


def _audit_prune(db: Session, count: int) -> None:
    log_action(
        db,
        actor_type=ActorType.SYSTEM,
        actor_id="cli",
        action="PRUNE_WORKLOAD_CERTS",
        target_type="Certificate",
        target_id=None,
        status=AuditStatus.SUCCESS,
        details={"deleted": count},
    )


def _cmd_crl_regenerate(db: Session, ca_name: str) -> int:
    candidates = [
        ca
        for ca in db.scalars(
            select(CertificateAuthority).where(
                CertificateAuthority.name == ca_name, CertificateAuthority.status == CAStatusEnum.ACTIVE
            )
        ).all()
        if pki_service.ca_has_key(ca)
    ]
    if not candidates:
        _error(f"no active CA named '{ca_name}' with a key")
        return 1
    if len(candidates) > 1:
        _error(f"CA name '{ca_name}' is ambiguous")
        return 1
    try:
        record = crl_service.regenerate_crl(db, candidates[0])
    except crl_service.CrlUnavailableError:
        _error("the CA key is unavailable, so no CRL was generated")
        return 1
    _emit(
        {
            "ca_id": candidates[0].id,
            "crl_number": record.crl_number,
            "this_update": _rfc3339(record.this_update),
            "next_update": _rfc3339(record.next_update),
            "revoked_count": record.revoked_count,
        }
    )
    return 0


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    session_factory: Optional[Callable[[], Session]] = None,
    keyring: Optional[keystore.KeyRing] = None,
) -> int:
    args = _build_parser().parse_args(argv)

    if args.group == "backup":
        return _cmd_backup(args.out_dir, args.keep)

    if keyring is None and (args.group in ("kek", "verify-db") or (args.group == "ca" and args.action == "import")):
        try:
            keyring = keystore.get_keyring()
        except keystore.KeystoreError as exc:
            _error(str(exc))
            return 1

    if args.group == "verify-db":
        assert keyring is not None  # loaded above
        return _cmd_verify_db(keyring, args.db)

    if session_factory is None:
        from app.db import SessionLocal

        session_factory = SessionLocal

    db = session_factory()
    try:
        if args.group == "kek":
            assert keyring is not None  # loaded above
            if args.action == "status":
                return _cmd_status(db, keyring)
            return _cmd_rewrap(db, keyring, args.to_kek_id, args.dry_run)
        if args.group == "ca":
            if args.action == "import-root-cert":
                return _cmd_import_root_cert(db, args.name, args.cert)
            assert keyring is not None  # loaded above
            return _cmd_import_ca(db, keyring, args.name, args.cert, args.chain)
        if args.group == "prune":
            return _cmd_prune(db, args.days, args.dry_run)
        return _cmd_crl_regenerate(db, args.ca_name)
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
