"""Tests for the in-cluster TokenReview client. No real network: httpx.MockTransport only."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.config import get_settings
from app.services.tokenreview import (
    SA_USERNAME_RE,
    InClusterTokenReviewer,
    NotAServiceAccount,
    ReviewedIdentity,
    TokenRejected,
    TokenReviewError,
    TokenReviewUnavailable,
    get_token_reviewer,
)

OWN_TOKEN = "own-sa-token-0123456789"
CALLER_TOKEN = "caller-token-abcdefghij"
USERNAME = "system:serviceaccount:mtls-demo:demo-client"


def _write_ca(path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kube-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


@pytest.fixture
def files(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text(OWN_TOKEN + "\n", encoding="utf-8")
    ca_file = tmp_path / "ca.crt"
    _write_ca(ca_file)
    return token_file, ca_file


def _review_body(
    *,
    authenticated: Any = True,
    audiences: Optional[list[str]] = None,
    username: Any = USERNAME,
    include_audiences: bool = True,
) -> dict[str, Any]:
    status: dict[str, Any] = {"authenticated": authenticated, "user": {"username": username}}
    if include_audiences:
        status["audiences"] = ["labca"] if audiences is None else audiences
    return {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "status": status}


def _reviewer(
    files,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    host: Optional[str] = "10.43.0.1",
    port: Optional[str] = "6443",
) -> InClusterTokenReviewer:
    token_file, ca_file = files
    return InClusterTokenReviewer(
        host=host,
        port=port,
        sa_token_file=str(token_file),
        ca_file=str(ca_file),
        transport=httpx.MockTransport(handler),
    )


def _json_response(body: Any, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=body)


def test_request_url_headers_and_body_are_exact(files):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json_response(_review_body())

    identity = _reviewer(files, handler).review(CALLER_TOKEN, "labca")

    assert identity == ReviewedIdentity(namespace="mtls-demo", service_account="demo-client", username=USERNAME)
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == "https://10.43.0.1:6443/apis/authentication.k8s.io/v1/tokenreviews"
    assert request.headers["authorization"] == f"Bearer {OWN_TOKEN}"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.content) == {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {"token": CALLER_TOKEN, "audiences": ["labca"]},
    }


def test_ipv6_host_is_bracketed(files):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json_response(_review_body())

    _reviewer(files, handler, host="fd00::1", port="6443").review(CALLER_TOKEN, "labca")

    assert str(seen[0].url) == "https://[fd00::1]:6443/apis/authentication.k8s.io/v1/tokenreviews"


def test_host_and_port_default_to_environment(files, monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json_response(_review_body())

    _reviewer(files, handler, host=None, port=None).review(CALLER_TOKEN, "labca")

    assert seen[0].url.host == "kubernetes.default.svc"


def test_own_token_file_is_reread_on_every_call(files):
    token_file, _ = files
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["authorization"])
        return _json_response(_review_body())

    reviewer = _reviewer(files, handler)
    reviewer.review(CALLER_TOKEN, "labca")
    token_file.write_text("rotated-token-xyz\n", encoding="utf-8")
    reviewer.review(CALLER_TOKEN, "labca")

    assert seen == [f"Bearer {OWN_TOKEN}", "Bearer rotated-token-xyz"]


@pytest.mark.parametrize(
    "body",
    [
        _review_body(authenticated=False),
        _review_body(authenticated="true"),
        _review_body(include_audiences=False),
        _review_body(audiences=["other"]),
        _review_body(audiences=[]),
        {"status": {}},
        {},
    ],
)
def test_unauthenticated_or_wrong_audience_is_rejected(files, body):
    with pytest.raises(TokenRejected):
        _reviewer(files, lambda request: _json_response(body)).review(CALLER_TOKEN, "labca")


def test_rejection_messages_name_the_condition(files):
    with pytest.raises(TokenRejected, match="token not authenticated"):
        _reviewer(files, lambda r: _json_response(_review_body(authenticated=False))).review(CALLER_TOKEN, "labca")
    with pytest.raises(TokenRejected, match="token audience mismatch"):
        _reviewer(files, lambda r: _json_response(_review_body(audiences=["x"]))).review(CALLER_TOKEN, "labca")


@pytest.mark.parametrize(
    "username",
    [
        "system:node:x",
        "alice",
        "system:serviceaccount:Bad:sa",
        "system:serviceaccount:ns:",
        "system:serviceaccount:ns",
        7,
    ],
)
def test_non_service_account_user_is_rejected(files, username):
    with pytest.raises(NotAServiceAccount):
        _reviewer(files, lambda r: _json_response(_review_body(username=username))).review(CALLER_TOKEN, "labca")


def test_service_account_name_may_contain_dots(files):
    username = "system:serviceaccount:team-a:worker.v2"
    identity = _reviewer(files, lambda r: _json_response(_review_body(username=username))).review(CALLER_TOKEN, "labca")
    assert (identity.namespace, identity.service_account) == ("team-a", "worker.v2")
    assert SA_USERNAME_RE.match(username)


def _raise(exc: Exception) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


@pytest.mark.parametrize(
    "handler",
    [
        lambda r: httpx.Response(500, text="boom"),
        lambda r: httpx.Response(401, text="no"),
        lambda r: httpx.Response(302, headers={"Location": "https://elsewhere.test/"}),
        lambda r: httpx.Response(200, text="not json"),
        lambda r: _json_response(["a", "list"]),
        _raise(httpx.ConnectTimeout("timed out")),
        _raise(httpx.ConnectError("refused")),
    ],
)
def test_api_failures_are_unavailable(files, handler):
    with pytest.raises(TokenReviewUnavailable):
        _reviewer(files, handler).review(CALLER_TOKEN, "labca")


def test_status_201_is_accepted(files):
    identity = _reviewer(files, lambda r: _json_response(_review_body(), 201)).review(CALLER_TOKEN, "labca")
    assert identity.namespace == "mtls-demo"


def test_missing_host_env_is_unavailable(files, monkeypatch):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.delenv("KUBERNETES_SERVICE_PORT", raising=False)
    reviewer = _reviewer(files, lambda r: _json_response(_review_body()), host=None, port=None)
    with pytest.raises(TokenReviewUnavailable, match="Kubernetes API is not configured."):
        reviewer.review(CALLER_TOKEN, "labca")


def test_missing_token_file_and_ca_file_are_unavailable(files, tmp_path):
    token_file, ca_file = files

    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(_review_body())

    transport = httpx.MockTransport(handler)
    no_token = InClusterTokenReviewer(
        host="h", port="1", sa_token_file=str(tmp_path / "absent"), ca_file=str(ca_file), transport=transport
    )
    no_ca = InClusterTokenReviewer(
        host="h", port="1", sa_token_file=str(token_file), ca_file=str(tmp_path / "absent"), transport=transport
    )
    for reviewer in (no_token, no_ca):
        with pytest.raises(TokenReviewUnavailable):
            reviewer.review(CALLER_TOKEN, "labca")


def test_tokens_never_appear_in_exceptions_or_repr(files, tmp_path):
    token_file, ca_file = files
    failures: list[Callable[[httpx.Request], httpx.Response]] = [
        lambda r: httpx.Response(500, text=f"echo {CALLER_TOKEN} {OWN_TOKEN}"),
        lambda r: httpx.Response(200, text=f"{CALLER_TOKEN} {OWN_TOKEN}"),
        _raise(httpx.ConnectTimeout(f"timed out {CALLER_TOKEN} {OWN_TOKEN}")),
        lambda r: _json_response(_review_body(authenticated=False)),
        lambda r: _json_response(_review_body(audiences=["x"])),
        lambda r: _json_response(_review_body(username=f"alice-{CALLER_TOKEN}")),
    ]
    for handler in failures:
        reviewer = _reviewer(files, handler)
        with pytest.raises(TokenReviewError) as info:
            reviewer.review(CALLER_TOKEN, "labca")
        for text in (str(info.value), repr(info.value), repr(reviewer)):
            assert CALLER_TOKEN not in text
            assert OWN_TOKEN not in text
        assert info.value.__cause__ is None
    unreadable = InClusterTokenReviewer(
        host="h", port="1", sa_token_file=str(tmp_path / "absent"), ca_file=str(ca_file)
    )
    with pytest.raises(TokenReviewUnavailable) as info:
        unreadable.review(CALLER_TOKEN, "labca")
    assert CALLER_TOKEN not in str(info.value) + repr(info.value)


def test_get_token_reviewer_is_cached_and_uses_settings(monkeypatch):
    monkeypatch.setenv("KUBE_SA_TOKEN_FILE", "/tmp/custom-token")
    monkeypatch.setenv("KUBE_CA_FILE", "/tmp/custom-ca")
    get_settings.cache_clear()
    get_token_reviewer.cache_clear()

    first = get_token_reviewer()

    assert get_token_reviewer() is first
    assert isinstance(first, InClusterTokenReviewer)
    assert first._sa_token_file == "/tmp/custom-token"
    assert first._ca_file == "/tmp/custom-ca"
