"""Validation of URI subject alternative names (SPIFFE IDs and https URLs)."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

MAX_URI_BYTES = 2048

_SPIFFE_PREFIX = "spiffe://"
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9._-]+$")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_ALLOWED_SCHEMES_MESSAGE = "Only spiffe:// and https:// URI SANs are allowed."


def is_spiffe_id(uri: str) -> bool:
    return isinstance(uri, str) and uri.startswith(_SPIFFE_PREFIX)


def validate_uri_san(uri: str) -> str:
    """Return ``uri`` unchanged or raise ``ValueError`` with a client-safe message."""
    if not isinstance(uri, str) or not uri:
        raise ValueError("URI SAN must be a non-empty string.")
    if len(uri.encode("utf-8")) > MAX_URI_BYTES:
        raise ValueError(f"URI SAN must be at most {MAX_URI_BYTES} bytes.")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in uri):
        raise ValueError("URI SAN must not contain whitespace or control characters.")
    if uri.startswith(_SPIFFE_PREFIX):
        _validate_spiffe(uri)
    elif uri.startswith("https://"):
        _validate_https(uri)
    else:
        raise ValueError(_ALLOWED_SCHEMES_MESSAGE)
    return uri


def _validate_spiffe(uri: str) -> None:
    rest = uri[len(_SPIFFE_PREFIX) :]
    trust_domain, sep, path = rest.partition("/")
    if not trust_domain or not _TRUST_DOMAIN_RE.match(trust_domain):
        raise ValueError("SPIFFE ID has an invalid trust domain.")
    if sep != "/" or not path:
        raise ValueError("SPIFFE ID must have a non-empty path.")
    for segment in path.split("/"):
        if not segment or segment in {".", ".."} or not _SEGMENT_RE.match(segment):
            raise ValueError("SPIFFE ID has an invalid path segment.")


def _validate_https(uri: str) -> None:
    try:
        parts = urlsplit(uri)
        hostname = parts.hostname
        username, password = parts.username, parts.password
    except ValueError:
        raise ValueError("URI SAN is not a valid https URL.") from None
    if parts.scheme != "https" or not hostname:
        raise ValueError("URI SAN is not a valid https URL.")
    if username is not None or password is not None:
        raise ValueError("URI SAN must not contain user information.")
    if parts.fragment:
        raise ValueError("URI SAN must not contain a fragment.")
