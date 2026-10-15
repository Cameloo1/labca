"""Tests for path classification."""

from __future__ import annotations

import pytest

from app.security.route_class import RouteClass, classify, classify_scope

P, M, A = RouteClass.PUBLIC, RouteClass.MACHINE, RouteClass.ADMIN


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/health", P),
        ("/ready", P),
        ("/healthz", A),
        ("/readyz", A),
        ("/pki", P),
        ("/pki/", P),
        ("/pki/index.json", P),
        ("/pkix", A),
        ("/static", P),
        ("/static/app.css", P),
        ("/staticx/app.css", A),
        ("/api", A),
        ("/api/", A),
        ("/api/v1", M),
        ("/api/v1/", M),
        ("/api/v1/certificates", M),
        ("/api/v1/workload/sign", M),
        ("/api/v1x", A),
        ("/", A),
        ("/cas", A),
        ("/docs", A),
        ("/redoc", A),
        ("/openapi.json", A),
        ("/no/such/page", A),
        ("", A),
    ],
)
def test_classification_table(path, expected):
    assert classify(path) is expected


@pytest.mark.parametrize(
    "path",
    [
        "/pki/../cas",
        "/pki/./index.json",
        "/pki//index.json",
        "//pki/index.json",
        "/pki/..",
        "/static/../cas",
        "/api/v1/../cas",
        "/api/v1//certificates",
        "/pki\\index.json",
        "/api/v1\\x",
    ],
)
def test_prefix_tricks_are_admin(path):
    assert classify(path) is A


@pytest.mark.parametrize(
    "raw_path",
    [b"/pki/%2e%2e/cas", b"/pki/%2E%2E/cas", b"/pki/..%2fcas", b"/pki%2Findex.json", b"/api/v1/%2e/x", b"/pki%5cx"],
)
def test_encoded_raw_path_is_admin(raw_path):
    assert classify("/pki/index.json", raw_path) is A
    assert classify_scope({"path": "/api/v1/certificates", "raw_path": raw_path}) is A


def test_clean_raw_path_keeps_class():
    assert classify_scope({"path": "/pki/index.json", "raw_path": b"/pki/index.json"}) is P
    assert classify_scope({"path": "/api/v1/x"}) is M
