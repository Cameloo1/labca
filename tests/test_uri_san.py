"""Tests for URI SAN validation."""

from __future__ import annotations

import pytest

from app.services.uri_san import MAX_URI_BYTES, is_spiffe_id, validate_uri_san

VALID = [
    "spiffe://labca.example/ns/a/sa/b",
    "spiffe://td-1.example_x/a.b-c_d",
    "https://example.com/x?y=1",
]

INVALID = [
    "spiffe://Labca.example/ns/a",
    "spiffe://labca.example",
    "spiffe://labca.example/",
    "spiffe://labca.example/a//b",
    "spiffe://labca.example/a/../b",
    "spiffe://labca.example/a/./b",
    "spiffe://labca.example:8443/a",
    "spiffe://user@labca.example/a",
    "spiffe://labca.example/a?x=1",
    "spiffe://labca.example/a#f",
    "spiffe://labca.example/a%20b",
    "spiffe:///a",
    "SPIFFE://labca.example/a",
    "http://example.com/",
    "https:///nohost",
    "https://u:p@example.com/",
    "https://example.com/#frag",
    "https://[::1",
    "urn:uuid:1234",
    "spiffe://labca.example/" + "a" * (MAX_URI_BYTES - len("spiffe://labca.example/") + 1),
    "spiffe://labca.example/a b",
    "spiffe://labca.example/a\tb",
    "",
]


@pytest.mark.parametrize("uri", VALID)
def test_valid_uri_sans_are_returned_unchanged(uri):
    assert validate_uri_san(uri) == uri


@pytest.mark.parametrize("uri", INVALID)
def test_invalid_uri_sans_are_rejected(uri):
    with pytest.raises(ValueError):
        validate_uri_san(uri)


def test_non_string_is_rejected():
    with pytest.raises(ValueError):
        validate_uri_san(None)  # type: ignore[arg-type]  # deliberate wrong type to test the guard


def test_scheme_message_is_fixed():
    with pytest.raises(ValueError, match="Only spiffe:// and https:// URI SANs are allowed."):
        validate_uri_san("urn:uuid:1234")


def test_is_spiffe_id():
    assert is_spiffe_id("spiffe://labca.example/a")
    assert not is_spiffe_id("https://example.com/")
