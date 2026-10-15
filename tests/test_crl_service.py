"""Tests for CRL generation, storage, refresh, and the post-revocation hook."""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app.config import get_settings
from app.models import (
    CASourceTypeEnum,
    CAStatusEnum,
    Certificate,
    CertificateAuthority,
    CertificateStatusEnum,
    CertificateTypeEnum,
    CrlRecord,
)
from app.schemas import RootCAConfig
from app.services import crl_service, keystore, revocation_service
from app.services.ca_service import create_root_ca
from app.services.crl_service import CrlUnavailableError, get_current_crl, regenerate_crl

NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ca(db_session, *, name="CRL Root", algorithm="ECDSA", curve="P-256") -> CertificateAuthority:
    config = RootCAConfig(
        name=name, subject_cn=name, validity_years=25, key_algorithm=algorithm, curve=curve, key_size=2048
    )
    ca = create_root_ca(config, db_session)
    db_session.commit()
    return ca


def _row(
    db_session,
    ca: CertificateAuthority,
    serial: str,
    *,
    revoked_at: datetime | None = None,
    code: str | None = None,
    reason: str | None = None,
    not_after: datetime | None = None,
) -> Certificate:
    cert = Certificate(
        ca_id=ca.id,
        type=CertificateTypeEnum.LEAF,
        common_name=f"leaf-{serial}",
        san_dns=[],
        san_ips=[],
        san_uris=[],
        serial_number=serial,
        not_before=NOW - timedelta(days=1),
        not_after=not_after or NOW + timedelta(days=30),
        key_algorithm="ECDSA",
        key_size=256,
        status=CertificateStatusEnum.REVOKED if revoked_at else CertificateStatusEnum.ACTIVE,
        environment_tags=[],
        cert_pem="PEM",
        is_ephemeral=False,
        revoked_at=revoked_at,
        revocation_reason=reason,
        revocation_reason_code=code,
    )
    db_session.add(cert)
    db_session.commit()
    return cert


def _parse(record: CrlRecord) -> x509.CertificateRevocationList:
    return x509.load_der_x509_crl(record.der)


def _ca_cert(ca: CertificateAuthority) -> x509.Certificate:
    return x509.load_pem_x509_certificate(ca.cert_pem.encode())


def _set_env(monkeypatch, **values: str) -> None:
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()


def test_empty_crl_parses_and_verifies(db_session):
    ca = _ca(db_session)
    ca_cert = _ca_cert(ca)

    record = regenerate_crl(db_session, ca, now=NOW)

    crl = _parse(record)
    assert record.crl_number == 1
    assert crl.issuer == ca_cert.subject
    ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == ski.digest
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 1
    assert crl.next_update_utc - crl.last_update_utc == timedelta(hours=24)
    assert crl.is_signature_valid(ca_cert.public_key())
    assert len(list(crl)) == 0
    assert record.revoked_count == 0


def test_revoked_serials_listed_with_reasons(db_session):
    ca = _ca(db_session)
    t0 = NOW - timedelta(hours=3)
    _row(db_session, ca, "a1", revoked_at=t0, code="keyCompromise")
    _row(db_session, ca, "b2", revoked_at=t0 + timedelta(minutes=1), code="superseded")
    _row(db_session, ca, "c3", revoked_at=t0 + timedelta(minutes=2), code="unspecified")

    crl = _parse(regenerate_crl(db_session, ca, now=NOW))

    entries = {entry.serial_number: entry for entry in crl}
    assert set(entries) == {0xA1, 0xB2, 0xC3}
    assert entries[0xA1].extensions.get_extension_for_class(x509.CRLReason).value.reason == (
        x509.ReasonFlags.key_compromise
    )
    assert entries[0xB2].extensions.get_extension_for_class(x509.CRLReason).value.reason == (
        x509.ReasonFlags.superseded
    )
    with pytest.raises(x509.ExtensionNotFound):
        entries[0xC3].extensions.get_extension_for_class(x509.CRLReason)
    assert entries[0xA1].revocation_date_utc == t0
    assert entries[0xB2].revocation_date_utc == t0 + timedelta(minutes=1)
    assert entries[0xC3].revocation_date_utc == t0 + timedelta(minutes=2)


def test_legacy_free_text_reason_mapped(db_session):
    ca = _ca(db_session)
    _row(db_session, ca, "d4", revoked_at=NOW - timedelta(hours=1), code=None, reason="ca_compromise")

    crl = _parse(regenerate_crl(db_session, ca, now=NOW))

    entry = next(iter(crl))
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.ca_compromise


def test_crl_number_increments(db_session):
    ca = _ca(db_session)

    numbers = [regenerate_crl(db_session, ca, now=NOW + timedelta(minutes=i)).crl_number for i in range(3)]

    assert numbers == [1, 2, 3]
    assert db_session.query(CrlRecord).filter(CrlRecord.ca_id == ca.id).count() == 1


def test_retention_excludes_long_expired(db_session, monkeypatch):
    ca = _ca(db_session)
    revoked = NOW - timedelta(days=2)
    _row(db_session, ca, "e1", revoked_at=revoked, not_after=NOW - timedelta(hours=2))
    _row(db_session, ca, "e2", revoked_at=revoked, not_after=NOW - timedelta(minutes=30))

    crl = _parse(regenerate_crl(db_session, ca, now=NOW))
    assert {entry.serial_number for entry in crl} == {0xE2}

    _set_env(monkeypatch, CRL_RETENTION_AFTER_EXPIRY_HOURS="0")
    crl = _parse(regenerate_crl(db_session, ca, now=NOW))
    assert len(list(crl)) == 0


def test_next_update_uses_setting(db_session, monkeypatch):
    ca = _ca(db_session)
    _set_env(monkeypatch, CRL_VALIDITY_HOURS="6")

    crl = _parse(regenerate_crl(db_session, ca, now=NOW))

    assert crl.next_update_utc - crl.last_update_utc == timedelta(hours=6)


def test_get_current_crl_reuses_fresh(db_session):
    ca = _ca(db_session)

    first = get_current_crl(db_session, ca, now=NOW)
    second = get_current_crl(db_session, ca, now=NOW + timedelta(minutes=5))

    assert first.crl_number == second.crl_number == 1


def test_get_current_crl_regenerates_after_half_life(db_session):
    ca = _ca(db_session)
    first = get_current_crl(db_session, ca, now=NOW)
    this_update = first.this_update

    second = get_current_crl(
        db_session, ca, now=this_update.replace(tzinfo=timezone.utc) + timedelta(hours=12, seconds=1)
    )

    assert second.crl_number == 2


def test_get_current_crl_regenerates_when_dirty(db_session):
    ca = _ca(db_session)
    revocation_service.clear_post_revoke_hooks()
    cert = _row(db_session, ca, "f5")
    first = get_current_crl(db_session, ca)
    assert first.crl_number == 1

    revocation_service.revoke_certificate(cert, "gone", db_session, reason_code="superseded")
    second = get_current_crl(db_session, ca)

    assert second.crl_number == 2
    assert {entry.serial_number for entry in _parse(second)} == {0xF5}


def test_revocation_hook_regenerates(db_session):
    ca = _ca(db_session)
    cert = _row(db_session, ca, "a7")
    assert regenerate_crl(db_session, ca).crl_number == 1

    revocation_service.revoke_certificate(cert, "leaked", db_session, reason_code="keyCompromise")

    record = db_session.query(CrlRecord).filter(CrlRecord.ca_id == ca.id).one()
    assert record.crl_number == 2
    crl = _parse(record)
    assert {entry.serial_number for entry in crl} == {0xA7}
    assert crl.is_signature_valid(_ca_cert(ca).public_key())


def test_hook_ignores_keyless_ca(db_session):
    now = datetime.now(timezone.utc)
    ca = CertificateAuthority(
        name="Keyless Root",
        source_type=CASourceTypeEnum.EXTERNAL_IMPORTED,
        subject_cn="Keyless Root",
        subject_json={"CN": "Keyless Root"},
        serial_number="REV-CA",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365),
        key_algorithm="RSA",
        key_size=4096,
        status=CAStatusEnum.ACTIVE,
        cert_pem="-----BEGIN CERTIFICATE-----root-----END CERTIFICATE-----",
    )
    db_session.add(ca)
    db_session.commit()
    cert = _row(db_session, ca, "REV-CERT")

    revoked = revocation_service.revoke_certificate(cert, "x", db_session)

    assert revoked.revoked_at is not None
    assert db_session.query(CrlRecord).count() == 0


def test_keyless_ca_raises_unavailable(db_session):
    ca = _ca(db_session)
    ca.key_encrypted_pem = None
    db_session.commit()

    with pytest.raises(CrlUnavailableError, match="no private key"):
        regenerate_crl(db_session, ca, now=NOW)


def _break_keyring(monkeypatch) -> None:
    monkeypatch.delenv("LABCA_KEK_TEST_1", raising=False)
    monkeypatch.setenv("LABCA_KEK_OTHER_1", base64.b64encode(bytes(range(1, 33))).decode())
    monkeypatch.setenv("LABCA_ACTIVE_KEK_ID", "other-1")
    get_settings.cache_clear()
    keystore.get_keyring.cache_clear()


def test_unsealable_key_raises_unavailable(db_session, monkeypatch):
    ca = _ca(db_session)
    _break_keyring(monkeypatch)

    with pytest.raises(CrlUnavailableError) as excinfo:
        regenerate_crl(db_session, ca, now=NOW)

    text = str(excinfo.value)
    assert text == "CA key is unavailable."
    assert "labca:v1:" not in text
    assert "PRIVATE KEY" not in text


def test_stale_record_served_when_key_unavailable(db_session, monkeypatch):
    ca = _ca(db_session)
    stored = regenerate_crl(db_session, ca, now=NOW)
    _break_keyring(monkeypatch)
    half_life_passed = NOW + timedelta(hours=13)

    served = get_current_crl(db_session, ca, now=half_life_passed)

    assert served.crl_number == stored.crl_number == 1
    with pytest.raises(CrlUnavailableError):
        get_current_crl(db_session, ca, now=NOW + timedelta(hours=24))


def test_non_hex_serial_skipped(db_session, caplog):
    ca = _ca(db_session)
    _row(db_session, ca, "REV-CERT", revoked_at=NOW - timedelta(hours=1))
    _row(db_session, ca, "ab", revoked_at=NOW - timedelta(hours=1))

    with caplog.at_level(logging.WARNING):
        record = regenerate_crl(db_session, ca, now=NOW)

    assert {entry.serial_number for entry in _parse(record)} == {0xAB}
    assert record.revoked_count == 1
    assert any("non-hex serial" in message for message in caplog.messages)


def test_p384_ca_uses_sha384(db_session):
    p384 = _ca(db_session, name="P384 Root", curve="P-384")
    rsa_ca = _ca(db_session, name="RSA Root", algorithm="RSA")

    p384_crl = _parse(regenerate_crl(db_session, p384, now=NOW))
    rsa_crl = _parse(regenerate_crl(db_session, rsa_ca, now=NOW))

    assert isinstance(p384_crl.signature_hash_algorithm, hashes.SHA384)
    assert isinstance(rsa_crl.signature_hash_algorithm, hashes.SHA256)
    assert crl_service.reason_code_for(Certificate(revocation_reason="nonsense")) == "unspecified"
