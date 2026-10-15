"""Tests for envelope encryption, token parsing, and keyring loading."""

from __future__ import annotations

import base64
import os

import pytest

from app.config import Settings
from app.services import keystore
from app.services.keystore import (
    IntegrityError,
    KeyRing,
    KeyringConfigError,
    LegacyFormatError,
    MalformedTokenError,
    NoActiveKekError,
    UnknownKekError,
    aad_for,
    load_keyring,
    parse_token,
)

KEK1 = bytes(range(32))
KEK2 = bytes(range(32, 64))
AAD = aad_for("certificates", "row-a", "stored_key_encrypted_pem")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64u(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _ring(active: str | None = "k1") -> KeyRing:
    return KeyRing({"k1": KEK1, "k2": KEK2}, active_kek_id=active)


def _flip_part(token: str, index: int) -> str:
    parts = token.split(":")
    raw = bytearray(_unb64u(parts[index]))
    raw[0] ^= 0x01
    parts[index] = _b64u(bytes(raw))
    return ":".join(parts)


def test_seal_unseal_round_trip():
    ring = _ring()
    for plaintext in (b"x", b"k" * 10240):
        token = ring.seal(plaintext, AAD)
        assert ring.unseal(token, AAD) == plaintext


def test_token_format():
    plaintext = b"private-key-bytes"
    token = _ring().seal(plaintext, AAD)
    assert token.startswith("labca:v1:k1:")
    assert "=" not in token
    parts = token.split(":")
    assert len(parts) == 6
    assert [len(_unb64u(p)) for p in parts[3:]] == [40, 12, len(plaintext) + 16]


def test_seal_is_randomized():
    ring = _ring()
    first = ring.seal(b"same", AAD).split(":")
    second = ring.seal(b"same", AAD).split(":")
    assert first[3] != second[3]
    assert first[4] != second[4]
    assert first[5] != second[5]


def test_tampered_ciphertext_raises_integrity_error():
    ring = _ring()
    token = _flip_part(ring.seal(b"secret", AAD), 5)
    with pytest.raises(IntegrityError):
        ring.unseal(token, AAD)


def test_tampered_nonce_raises_integrity_error():
    ring = _ring()
    token = _flip_part(ring.seal(b"secret", AAD), 4)
    with pytest.raises(IntegrityError):
        ring.unseal(token, AAD)


def test_tampered_wrapped_key_raises_integrity_error():
    ring = _ring()
    token = _flip_part(ring.seal(b"secret", AAD), 3)
    with pytest.raises(IntegrityError):
        ring.unseal(token, AAD)


def test_aad_row_swap_raises_integrity_error():
    ring = _ring()
    token = ring.seal(b"secret", AAD)
    with pytest.raises(IntegrityError):
        ring.unseal(token, aad_for("certificates", "row-b", "stored_key_encrypted_pem"))
    with pytest.raises(IntegrityError):
        ring.unseal(token, aad_for("certificates", "row-a", "key_encrypted_pem"))


def test_unknown_kek_raises():
    token = _ring().seal(b"secret", AAD)
    only_k2 = KeyRing({"k2": KEK2}, active_kek_id="k2")
    with pytest.raises(UnknownKekError):
        only_k2.unseal(token, AAD)


def test_legacy_value_raises_legacy_format_error():
    with pytest.raises(LegacyFormatError):
        _ring().unseal("enc::" + _b64(b"old"), AAD)
    with pytest.raises(LegacyFormatError):
        parse_token("enc::")


def _good_parts() -> list[str]:
    return ["labca", "v1", "k1", _b64u(os.urandom(40)), _b64u(os.urandom(12)), _b64u(os.urandom(32))]


def _with(index: int, value: str) -> str:
    parts = _good_parts()
    parts[index] = value
    return ":".join(parts)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "labca:v1:",
        ":".join(_good_parts()[:5]),
        ":".join(_good_parts() + ["extra"]),
        "labca:v2:" + ":".join(_good_parts()[2:]),
        _with(2, "K1"),
        _with(3, _b64u(os.urandom(40)) + "="),
        _with(4, "ab+defghijklmnop"),
        _with(5, ""),
        _with(4, _b64u(os.urandom(11))),
        _with(3, _b64u(os.urandom(39))),
        _with(5, _b64u(os.urandom(15))),
    ],
)
def test_malformed_tokens(token):
    with pytest.raises(MalformedTokenError):
        parse_token(token)


def test_rotation_rewrap_then_remove_old_kek():
    ring = _ring()
    plaintext = b"rotate-me"
    old = ring.seal(plaintext, AAD)
    new = ring.rewrap(old, AAD, "k2")
    old_parts, new_parts = old.split(":"), new.split(":")
    assert new_parts[2] == "k2"
    assert new_parts[4:] == old_parts[4:]
    assert new_parts[3] != old_parts[3]
    assert KeyRing({"k2": KEK2}).unseal(new, AAD) == plaintext
    with pytest.raises(UnknownKekError):
        KeyRing({"k1": KEK1}).unseal(new, AAD)


def test_rewrap_same_kek_returns_same_token():
    ring = _ring()
    token = ring.seal(b"stay", AAD)
    assert ring.rewrap(token, AAD, "k1") == token


def test_rewrap_with_wrong_aad_raises_integrity_error():
    ring = _ring()
    token = ring.seal(b"secret", AAD)
    wrong = aad_for("certificates", "row-z", "stored_key_encrypted_pem")
    with pytest.raises(IntegrityError):
        ring.rewrap(token, wrong, "k2")
    with pytest.raises(IntegrityError):
        ring.rewrap(token, wrong, "k1")


def test_rewrap_to_unknown_kek_raises():
    ring = _ring()
    with pytest.raises(UnknownKekError):
        ring.rewrap(ring.seal(b"secret", AAD), AAD, "missing")


def test_seal_without_active_kek_raises_no_active_kek():
    with pytest.raises(NoActiveKekError):
        _ring(active=None).seal(b"secret", AAD)


def test_seal_with_unloaded_active_kek_raises_unknown_kek():
    with pytest.raises(UnknownKekError):
        _ring(active="ghost").seal(b"secret", AAD)


def test_keyring_rejects_bad_id_and_bad_length():
    with pytest.raises(KeyringConfigError):
        KeyRing({"Bad_ID": KEK1})
    with pytest.raises(KeyringConfigError):
        KeyRing({"k" * 33: KEK1})
    with pytest.raises(KeyringConfigError):
        KeyRing({"k1": b"short"})


def test_keyring_sources_default_and_copy():
    ring = KeyRing({"k1": KEK1}, sources={"k1": "file", "unknown": "env"})
    assert ring.sources == {"k1": "file"}
    ring.sources["k1"] = "changed"
    assert ring.sources == {"k1": "file"}
    assert KeyRing({"k1": KEK1}).sources == {"k1": "memory"}
    assert ring.kek_ids == ["k1"]
    assert ring.has("k1") and not ring.has("k2")


def test_repr_and_errors_contain_no_key_material(tmp_path):
    ring = _ring()
    token = ring.seal(b"secret-plaintext", AAD)
    forbidden = [_b64(KEK1), _b64(KEK2), b"secret-plaintext".decode(), *token.split(":")[3:]]
    errors: list[Exception] = []
    for action in (
        lambda: ring.unseal(_flip_part(token, 5), AAD),
        lambda: ring.unseal(_flip_part(token, 3), AAD),
        lambda: KeyRing({"k2": KEK2}).unseal(token, AAD),
        lambda: parse_token("labca:v1:k1:a:b:c"),
        lambda: parse_token("enc::" + _b64(b"x")),
        lambda: _ring(active=None).seal(b"x", AAD),
        lambda: _ring(active="ghost").seal(b"x", AAD),
        lambda: ring.rewrap(token, AAD, "nope"),
        lambda: KeyRing({"k1": b"short"}),
    ):
        with pytest.raises(keystore.KeystoreError) as info:
            action()
        errors.append(info.value)
    texts = [str(e) for e in errors] + [repr(ring), repr(parse_token(token))]
    for text in texts:
        for secret in forbidden:
            assert secret not in text
    assert repr(ring) == "KeyRing(kek_ids=['k1', 'k2'], active_kek_id='k1')"
    assert repr(parse_token(token)).startswith("SealedToken(kek_id='k1', ciphertext_len=")
    assert keystore.kek_id_of(token) == "k1"


# ---- load_keyring ----


def _settings(**values) -> Settings:
    defaults = {"ENV": "dev", "LABCA_KEK_DIR": "", "LABCA_ACTIVE_KEK_ID": ""}
    return Settings(_env_file=None, **{**defaults, **values})


def test_load_from_dir(tmp_path):
    (tmp_path / "k1").write_text(_b64(KEK1) + "\n")
    (tmp_path / "k2").write_text(_b64(KEK2))
    ring = load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path), LABCA_ACTIVE_KEK_ID="k2"), {})
    assert ring.kek_ids == ["k1", "k2"]
    assert ring.sources == {"k1": "file", "k2": "file"}
    assert ring.active_kek_id == "k2"
    assert ring.unseal(KeyRing({"k1": KEK1}, "k1").seal(b"p", AAD), AAD) == b"p"


def test_load_from_dir_ignores_dot_entries(tmp_path):
    (tmp_path / "..data").mkdir()
    (tmp_path / "..2026_10_14_00_00_00.123").mkdir()
    (tmp_path / ".hidden").write_text("not a key")
    (tmp_path / "k1").write_text(_b64(KEK1))
    ring = load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path)), {})
    assert ring.kek_ids == ["k1"]
    assert ring.active_kek_id is None


def test_load_from_dir_follows_symlinks(tmp_path):
    target = tmp_path / "store"
    target.mkdir()
    (target / "real").write_text(_b64(KEK1))
    keys = tmp_path / "keys"
    keys.mkdir()
    try:
        os.symlink(target / "real", keys / "k1")
    except (OSError, NotImplementedError):  # pragma: no cover - symlinks unavailable
        pytest.fail("symlink creation is required for this test")
    assert load_keyring(_settings(LABCA_KEK_DIR=str(keys)), {}).kek_ids == ["k1"]


def test_load_from_dir_rejects_non_regular_entry(tmp_path):
    (tmp_path / "subdir").mkdir()
    with pytest.raises(KeyringConfigError, match="subdir"):
        load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path)), {})


def test_load_from_dir_rejects_bad_filename(tmp_path):
    (tmp_path / "Bad_Name.txt").write_text(_b64(KEK1))
    with pytest.raises(KeyringConfigError, match="Bad_Name.txt"):
        load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path)), {})


def test_load_rejects_wrong_length(tmp_path):
    (tmp_path / "k1").write_text(_b64(b"too-short"))
    with pytest.raises(KeyringConfigError, match="k1"):
        load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path)), {})
    with pytest.raises(KeyringConfigError, match="LABCA_KEK_SHORT"):
        load_keyring(_settings(), {"LABCA_KEK_SHORT": _b64(b"too-short")})


def test_load_rejects_invalid_base64(tmp_path):
    (tmp_path / "k1").write_text("!!!not base64!!!")
    with pytest.raises(KeyringConfigError, match="k1"):
        load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path)), {})
    with pytest.raises(KeyringConfigError, match="LABCA_KEK_BAD"):
        load_keyring(_settings(), {"LABCA_KEK_BAD": "%%%"})


def test_load_rejects_binary_kek_file_without_quoting_bytes(tmp_path):
    (tmp_path / "k1").write_bytes(b"\xff\xfe" + KEK1)
    with pytest.raises(KeyringConfigError, match="k1") as info:
        load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path)), {})
    assert "xff" not in str(info.value) and info.value.__cause__ is None and info.value.__suppress_context__


def test_load_rejects_missing_dir(tmp_path):
    with pytest.raises(KeyringConfigError):
        load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path / "missing")), {})


def test_load_from_env_maps_name_to_id():
    environ = {
        "LABCA_KEK_DEV_1": _b64(KEK1),
        "LABCA_KEK_DIR": "/not/a/kek",
        "UNRELATED": "x",
    }
    ring = load_keyring(_settings(), environ)
    assert ring.kek_ids == ["dev-1"]
    assert ring.sources == {"dev-1": "env"}


def test_duplicate_id_in_dir_and_env_rejected(tmp_path):
    (tmp_path / "dev-1").write_text(_b64(KEK1))
    with pytest.raises(KeyringConfigError, match="dev-1"):
        load_keyring(_settings(LABCA_KEK_DIR=str(tmp_path)), {"LABCA_KEK_DEV_1": _b64(KEK2)})


def test_prod_rejects_env_keks():
    with pytest.raises(KeyringConfigError, match="LABCA_KEK_DEV_1"):
        load_keyring(_settings(ENV="prod"), {"LABCA_KEK_DEV_1": _b64(KEK1)})
    with pytest.raises(KeyringConfigError, match="not allowed when ENV=prod"):
        load_keyring(_settings(ENV="PROD"), {"LABCA_KEK_DEV_1": _b64(KEK1)})


def test_prod_accepts_dir_keks(tmp_path):
    (tmp_path / "prod-1").write_text(_b64(KEK1))
    ring = load_keyring(
        _settings(ENV="prod", LABCA_KEK_DIR=str(tmp_path), LABCA_ACTIVE_KEK_ID="prod-1"),
        {"LABCA_KEK_DIR": str(tmp_path)},
    )
    assert ring.kek_ids == ["prod-1"]
    assert ring.active_kek_id == "prod-1"


def test_empty_strings_mean_unset():
    ring = load_keyring(_settings(LABCA_KEK_DIR="", LABCA_ACTIVE_KEK_ID=""), {"LABCA_KEK_DIR": ""})
    assert ring.kek_ids == []
    assert ring.active_kek_id is None


def test_module_level_helpers_use_cached_keyring():
    # conftest installs LABCA_KEK_TEST_1 and LABCA_ACTIVE_KEK_ID=test-1.
    token = keystore.seal_ca_key("ca-1", b"ca-secret")
    assert token.startswith("labca:v1:test-1:")
    assert keystore.unseal_ca_key("ca-1", token) == b"ca-secret"
    cert_token = keystore.seal_cert_key("c-1", b"cert-secret")
    assert keystore.unseal_cert_key("c-1", cert_token) == b"cert-secret"
    assert (
        keystore.rewrap(cert_token, aad_for("certificates", "c-1", "stored_key_encrypted_pem"), "test-1") == cert_token
    )
    raw = keystore.seal(b"raw", AAD)
    assert keystore.unseal(raw, AAD) == b"raw"
    assert keystore.get_keyring() is keystore.get_keyring()
