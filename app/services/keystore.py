"""Envelope encryption for stored private keys.

Each record is encrypted with AES-256-GCM under a fresh random 32-byte data
encryption key (DEK). The DEK is wrapped with AES Key Wrap (RFC 3394) under a
versioned key encryption key (KEK). The additional authenticated data (AAD)
binds a ciphertext to its table, row id, and column, so a value copied to
another row or column fails authentication.

Token format: ``labca:v1:<kek_id>:<wrapped_dek>:<nonce>:<ciphertext>`` where the
three data parts are URL-safe base64 without padding.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Mapping, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from app.config import Settings, get_settings

TOKEN_PREFIX = "labca:v1:"
LEGACY_PREFIX = "enc::"
KEK_ID_PATTERN = re.compile(r"^[a-z0-9-]{1,32}$")
ENV_KEK_PATTERN = re.compile(r"^LABCA_KEK_([A-Z0-9_]{1,32})$")  # LABCA_KEK_DIR is reserved and never a KEK
CA_KEY_TABLE, CA_KEY_COLUMN = "certificate_authorities", "key_encrypted_pem"
CERT_KEY_TABLE, CERT_KEY_COLUMN = "certificates", "stored_key_encrypted_pem"
SEALED_COLUMNS: tuple[tuple[str, str], ...] = (
    (CA_KEY_TABLE, CA_KEY_COLUMN),
    (CERT_KEY_TABLE, CERT_KEY_COLUMN),
)

_DATA_PART_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_KEK_DIR_VAR = "LABCA_KEK_DIR"
_KEK_LENGTH = 32
_WRAPPED_DEK_LENGTH = 40
_NONCE_LENGTH = 12
_MIN_CIPHERTEXT_LENGTH = 16


class KeystoreError(Exception):
    """Base class for keystore failures. Messages never contain key material."""


class KeyringConfigError(KeystoreError):
    """Bad KEK dir, file, env var, duplicate id, or env KEK in prod."""


class NoActiveKekError(KeystoreError):
    """A seal or rewrap needs an active KEK and none is configured."""


class UnknownKekError(KeystoreError):
    """A token or target references a KEK id that is not loaded."""


class IntegrityError(KeystoreError):
    """GCM tag failure or AES key unwrap failure."""


class LegacyFormatError(KeystoreError):
    """Input uses the legacy enc:: placeholder format."""


class MalformedTokenError(KeystoreError):
    """Input is not a valid labca:v1 token."""


def aad_for(table: str, row_id: str, column: str) -> bytes:
    return f"{table}:{row_id}:{column}".encode("utf-8")


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(part: str) -> bytes:
    padding = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + padding)


@dataclass(frozen=True)
class SealedToken:
    kek_id: str
    wrapped_dek: bytes
    nonce: bytes
    ciphertext: bytes

    def __repr__(self) -> str:
        return f"SealedToken(kek_id={self.kek_id!r}, ciphertext_len={len(self.ciphertext)})"


def parse_token(token: str) -> SealedToken:
    if token.startswith(LEGACY_PREFIX):
        raise LegacyFormatError("Legacy enc:: value; run 'alembic upgrade head' to convert it.")
    if not token.startswith(TOKEN_PREFIX):
        raise MalformedTokenError("Value is not a labca:v1 token.")
    parts = token.split(":")
    if len(parts) != 6:
        raise MalformedTokenError("Token does not have the expected number of parts.")
    kek_id = parts[2]
    data_parts = parts[3:]
    if not KEK_ID_PATTERN.match(kek_id):
        raise MalformedTokenError("Token has an invalid KEK id.")
    for part in data_parts:
        if not part or not _DATA_PART_PATTERN.match(part):
            raise MalformedTokenError("Token has an invalid data part.")
    try:
        wrapped_dek, nonce, ciphertext = (_b64u_decode(part) for part in data_parts)
    except (binascii.Error, ValueError):
        raise MalformedTokenError("Token data is not valid base64.") from None
    if len(wrapped_dek) != _WRAPPED_DEK_LENGTH:
        raise MalformedTokenError("Token wrapped key has the wrong length.")
    if len(nonce) != _NONCE_LENGTH:
        raise MalformedTokenError("Token nonce has the wrong length.")
    if len(ciphertext) < _MIN_CIPHERTEXT_LENGTH:
        raise MalformedTokenError("Token ciphertext is too short.")
    return SealedToken(kek_id=kek_id, wrapped_dek=wrapped_dek, nonce=nonce, ciphertext=ciphertext)


def kek_id_of(token: str) -> str:
    return parse_token(token).kek_id


class KeyRing:
    def __init__(
        self,
        keks: Mapping[str, bytes],
        active_kek_id: Optional[str] = None,
        sources: Optional[Mapping[str, str]] = None,
    ) -> None:
        for kek_id, key in keks.items():
            if not KEK_ID_PATTERN.match(kek_id):
                raise KeyringConfigError(f"Invalid KEK id '{kek_id}'.")
            if len(key) != _KEK_LENGTH:
                raise KeyringConfigError(f"KEK '{kek_id}' must be exactly {_KEK_LENGTH} bytes.")
        self._keks: dict[str, bytes] = {kek_id: bytes(key) for kek_id, key in keks.items()}
        self._active_kek_id = active_kek_id
        self._sources: dict[str, str] = {kek_id: "memory" for kek_id in self._keks}
        if sources:
            for kek_id, source in sources.items():
                if kek_id in self._sources:
                    self._sources[kek_id] = source

    @property
    def kek_ids(self) -> list[str]:
        return sorted(self._keks)

    @property
    def active_kek_id(self) -> Optional[str]:
        return self._active_kek_id

    @property
    def sources(self) -> dict[str, str]:
        return dict(self._sources)

    def has(self, kek_id: str) -> bool:
        return kek_id in self._keks

    def seal(self, plaintext: bytes, aad: bytes) -> str:
        if self._active_kek_id is None:
            raise NoActiveKekError(
                "No active KEK is configured. Set LABCA_ACTIVE_KEK_ID and provide KEKs via "
                "LABCA_KEK_DIR or LABCA_KEK_<ID>."
            )
        kek = self._keks.get(self._active_kek_id)
        if kek is None:
            raise UnknownKekError(f"KEK '{self._active_kek_id}' is not loaded")
        dek = os.urandom(32)
        nonce = os.urandom(_NONCE_LENGTH)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
        wrapped = aes_key_wrap(kek, dek)
        return (
            f"{TOKEN_PREFIX}{self._active_kek_id}:{_b64u_encode(wrapped)}:{_b64u_encode(nonce)}:"
            f"{_b64u_encode(ciphertext)}"
        )

    def _unwrap_dek(self, parsed: SealedToken) -> bytes:
        kek = self._keks.get(parsed.kek_id)
        if kek is None:
            raise UnknownKekError(f"KEK '{parsed.kek_id}' is not loaded")
        try:
            return aes_key_unwrap(kek, parsed.wrapped_dek)
        except InvalidUnwrap:
            raise IntegrityError("Key unwrap failed: wrong KEK or corrupted token.") from None

    def _decrypt(self, parsed: SealedToken, dek: bytes, aad: bytes) -> bytes:
        try:
            return AESGCM(dek).decrypt(parsed.nonce, parsed.ciphertext, aad)
        except InvalidTag:
            raise IntegrityError("Authentication failed: corrupted token or wrong record binding.") from None

    def unseal(self, token: str, aad: bytes) -> bytes:
        parsed = parse_token(token)
        dek = self._unwrap_dek(parsed)
        return self._decrypt(parsed, dek, aad)

    def rewrap(self, token: str, aad: bytes, to_kek_id: str) -> str:
        target = self._keks.get(to_kek_id)
        if target is None:
            raise UnknownKekError(f"KEK '{to_kek_id}' is not loaded")
        parsed = parse_token(token)
        if parsed.kek_id == to_kek_id:
            self.unseal(token, aad)
            return token
        dek = self._unwrap_dek(parsed)
        self._decrypt(parsed, dek, aad)  # verify the GCM tag; plaintext is discarded
        wrapped = aes_key_wrap(target, dek)
        parts = token.split(":")
        return f"{TOKEN_PREFIX}{to_kek_id}:{_b64u_encode(wrapped)}:{parts[4]}:{parts[5]}"

    def __repr__(self) -> str:
        return f"KeyRing(kek_ids={self.kek_ids!r}, active_kek_id={self._active_kek_id!r})"


def _decode_kek(raw: str, label: str) -> bytes:
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise KeyringConfigError(f"KEK {label} is not valid base64.") from None
    if len(key) != _KEK_LENGTH:
        raise KeyringConfigError(f"KEK {label} must decode to exactly {_KEK_LENGTH} bytes.")
    return key


def load_keyring(settings: Optional[Settings] = None, environ: Optional[Mapping[str, str]] = None) -> KeyRing:
    settings = settings or get_settings()
    environ = os.environ if environ is None else environ
    prod = settings.ENV.lower() == "prod"
    keks: dict[str, bytes] = {}
    sources: dict[str, str] = {}

    kek_dir = settings.LABCA_KEK_DIR or None
    if kek_dir:
        if not os.path.isdir(kek_dir):
            raise KeyringConfigError("LABCA_KEK_DIR is not an existing directory.")
        for name in sorted(os.listdir(kek_dir)):
            if name.startswith("."):
                continue
            if not KEK_ID_PATTERN.match(name):
                raise KeyringConfigError(f"KEK file name '{name}' is not a valid KEK id.")
            path = os.path.join(kek_dir, name)
            if not os.path.isfile(path):  # isfile follows symlinks
                raise KeyringConfigError(f"KEK file '{name}' is not a regular file.")
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    content = handle.read()
            except (OSError, UnicodeDecodeError):  # decode errors quote raw bytes, so never chain them
                raise KeyringConfigError(f"KEK file '{name}' cannot be read as text.") from None
            keks[name] = _decode_kek(content, f"file '{name}'")
            sources[name] = "file"

    env_matches = [
        (name, match)
        for name in sorted(environ)
        if name != _KEK_DIR_VAR and (match := ENV_KEK_PATTERN.match(name)) is not None
    ]
    if env_matches and prod:
        raise KeyringConfigError(
            "KEKs from environment variables are not allowed when ENV=prod: " + ", ".join(n for n, _ in env_matches)
        )
    for name, match in env_matches:
        kek_id = match.group(1).lower().replace("_", "-")  # always matches KEK_ID_PATTERN
        if kek_id in keks:
            raise KeyringConfigError(f"KEK id '{kek_id}' is defined more than once.")
        keks[kek_id] = _decode_kek(environ[name], f"environment variable {name}")
        sources[kek_id] = "env"

    return KeyRing(keks, active_kek_id=settings.LABCA_ACTIVE_KEK_ID or None, sources=sources)


@lru_cache(maxsize=1)
def get_keyring() -> KeyRing:
    return load_keyring(get_settings(), os.environ)


def seal(plaintext: bytes, aad: bytes) -> str:
    return get_keyring().seal(plaintext, aad)


def unseal(token: str, aad: bytes) -> bytes:
    return get_keyring().unseal(token, aad)


def rewrap(token: str, aad: bytes, to_kek_id: str) -> str:
    return get_keyring().rewrap(token, aad, to_kek_id)


def seal_ca_key(ca_id: str, pem: bytes) -> str:
    return seal(pem, aad_for(CA_KEY_TABLE, ca_id, CA_KEY_COLUMN))


def unseal_ca_key(ca_id: str, token: str) -> bytes:
    return unseal(token, aad_for(CA_KEY_TABLE, ca_id, CA_KEY_COLUMN))


def seal_cert_key(cert_id: str, pem: bytes) -> str:
    return seal(pem, aad_for(CERT_KEY_TABLE, cert_id, CERT_KEY_COLUMN))


def unseal_cert_key(cert_id: str, token: str) -> bytes:
    return unseal(token, aad_for(CERT_KEY_TABLE, cert_id, CERT_KEY_COLUMN))
