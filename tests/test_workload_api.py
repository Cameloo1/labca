"""Tests for POST /api/v1/workload/sign and /revoke."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Optional, Union

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.config import get_settings
from app.main import app
from app.models import ActorType, AuditLog, AuditStatus, CAStatusEnum, Certificate, CertificateAuthority
from app.schemas import IssueFromCAConfig
from app.services.cert_issuance_service import issue_cert_from_ca
from app.services.tokenreview import (
    NotAServiceAccount,
    ReviewedIdentity,
    TokenRejected,
    TokenReviewError,
    TokenReviewUnavailable,
    get_token_reviewer,
)
from tests.test_csr_signing import _csr, _tamper, _token
from tests.test_pki_routes import _keyless, _root, _sub

TRUST_DOMAIN = "labca.example.test"
CLIENT_ID = f"spiffe://{TRUST_DOMAIN}/ns/mtls-demo/sa/demo-client"
SERVER_ID = f"spiffe://{TRUST_DOMAIN}/ns/mtls-demo/sa/demo-server"
CLIENT_TOKEN = "tok-demo-client-0123456789"
SERVER_TOKEN = "tok-demo-server-9876543210"
SIGN = "/api/v1/workload/sign"
REVOKE = "/api/v1/workload/revoke"
ALLOWLIST = "mtls-demo/demo-server,mtls-demo/demo-client,mtls-demo/mtls-verifier"


class FakeTokenReviewer:
    def __init__(self) -> None:
        self.results: dict[str, Union[ReviewedIdentity, TokenReviewError]] = {}
        self.audiences: list[str] = []

    def add(self, token: str, namespace: str, service_account: str) -> None:
        username = f"system:serviceaccount:{namespace}:{service_account}"
        self.results[token] = ReviewedIdentity(namespace, service_account, username)

    def review(self, token: str, audience: str) -> ReviewedIdentity:
        self.audiences.append(audience)
        result = self.results.get(token)
        if result is None:
            raise TokenRejected("token not authenticated")
        if isinstance(result, Exception):
            raise result
        return result


@dataclass
class Env:
    client: Any
    db: Any
    monkeypatch: Any
    reviewer: FakeTokenReviewer
    root: CertificateAuthority
    sub: CertificateAuthority
    extra: dict[str, Any] = field(default_factory=dict)

    def setenv(self, **values: str) -> None:
        for key, value in values.items():
            self.monkeypatch.setenv(key, value)
        get_settings.cache_clear()

    def sign(self, csr_pem: Optional[str] = None, *, token: Optional[str] = CLIENT_TOKEN, **kwargs: Any):
        if csr_pem is not None and "json" not in kwargs and "content" not in kwargs:
            kwargs["json"] = {"csr_pem": csr_pem}
        headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
        headers.update(kwargs.pop("headers", {}))
        return self.client.post(SIGN, headers=headers, **kwargs)

    def revoke(self, body: Any, *, token: Optional[str] = CLIENT_TOKEN, **kwargs: Any):
        headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
        return self.client.post(REVOKE, headers=headers, json=body, **kwargs)

    def issue(self, token: str = CLIENT_TOKEN) -> dict[str, Any]:
        csr_pem, _ = _csr()
        response = self.sign(csr_pem, token=token)
        assert response.status_code == 201, response.text
        return response.json()

    def audit_rows(self, action: str) -> list[AuditLog]:
        self.db.expire_all()
        return list(self.db.query(AuditLog).filter(AuditLog.action == action).order_by(AuditLog.timestamp).all())

    def certificate_count(self) -> int:
        return self.db.query(Certificate).count()


@pytest.fixture
def env(client, db_session, monkeypatch) -> Env:
    root = _root(db_session, name="Workload Root")
    sub = _sub(db_session, root, name="Workload Issuing CA")
    reviewer = FakeTokenReviewer()
    reviewer.add(CLIENT_TOKEN, "mtls-demo", "demo-client")
    reviewer.add(SERVER_TOKEN, "mtls-demo", "demo-server")
    app.dependency_overrides[get_token_reviewer] = lambda: reviewer
    environment = Env(client, db_session, monkeypatch, reviewer, root, sub)
    environment.setenv(
        WORKLOAD_ISSUANCE_ENABLED="true",
        WORKLOAD_TRUST_DOMAIN=TRUST_DOMAIN,
        WORKLOAD_ISSUER_CA_NAME=sub.name,
        WORKLOAD_ALLOWLIST=ALLOWLIST,
    )
    environment.extra["base"] = environment.certificate_count()
    return environment


def _cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


def _assert_error(response, status_code: int, code: str) -> dict[str, Any]:
    assert response.status_code == status_code, response.text
    body = response.json()
    assert body["error"] == code
    assert isinstance(body["detail"], str) and body["detail"]
    assert response.headers["cache-control"] == "no-store"
    return body


def test_sign_allowlisted_success(env):
    csr_pem, key = _csr()

    response = env.sign(csr_pem)

    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {
        "spiffe_id",
        "serial_hex",
        "not_before",
        "not_after",
        "certificate_pem",
        "chain_pem",
        "trust_bundle_pem",
    }
    assert body["spiffe_id"] == CLIENT_ID
    leaf = _cert(body["certificate_pem"])
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [CLIENT_ID]
    assert san.get_values_for_type(x509.DNSName) == [
        "demo-client.mtls-demo.svc",
        "demo-client.mtls-demo.svc.cluster.local",
    ]
    assert san.get_values_for_type(x509.IPAddress) == []
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert set(eku) == {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH}
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "demo-client"
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc == timedelta(minutes=60)
    assert body["not_before"] == leaf.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert body["not_after"] == leaf.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    sub_cert = _cert(env.sub.cert_pem)
    root_cert = _cert(env.root.cert_pem)
    leaf.verify_directly_issued_by(sub_cert)
    assert leaf.public_key() == key.public_key()  # type: ignore[attr-defined]  # _csr returns an EC key here
    assert x509.load_pem_x509_certificates(body["chain_pem"].encode()) == [leaf, sub_cert]
    assert x509.load_pem_x509_certificates(body["trust_bundle_pem"].encode()) == [root_cert]
    assert body["serial_hex"] == format(leaf.serial_number, "x")

    row = env.db.query(Certificate).filter(Certificate.serial_number == body["serial_hex"]).one()
    assert row.issued_to_spiffe_id == CLIENT_ID
    assert row.environment_tags == ["workload"]
    assert row.ca_id == env.sub.id
    assert env.reviewer.audiences == ["labca"]


def test_sign_ignores_csr_subject_and_sans(env):
    csr_pem, _ = _csr(
        cn="evil",
        dns=("evil.example",),
        ips=("10.9.9.9",),
        uris=("spiffe://labca.example.test/ns/kube-system/sa/admin",),
    )

    response = env.sign(csr_pem)

    assert response.status_code == 201
    leaf = _cert(response.json()["certificate_pem"])
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [CLIENT_ID]
    assert san.get_values_for_type(x509.DNSName) == [
        "demo-client.mtls-demo.svc",
        "demo-client.mtls-demo.svc.cluster.local",
    ]
    assert san.get_values_for_type(x509.IPAddress) == []
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "demo-client"


def test_ttl_setting(env):
    env.setenv(WORKLOAD_CERT_TTL_MINUTES="15")

    response = env.sign(_csr()[0])

    assert response.status_code == 201
    leaf = _cert(response.json()["certificate_pem"])
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc == timedelta(minutes=15)


def test_custom_audience_is_passed_to_reviewer(env):
    env.setenv(WORKLOAD_TOKEN_AUDIENCE="custom-aud")

    assert env.sign(_csr()[0]).status_code == 201
    assert env.reviewer.audiences == ["custom-aud"]


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}, {"Authorization": "Bearer " + "x" * 16385}],
    ids=["no-header", "basic", "empty-bearer", "oversized"],
)
def test_missing_or_malformed_bearer_401(env, headers):
    response = env.client.post(SIGN, headers=headers, json={"csr_pem": _csr()[0]})
    revoke = env.client.post(REVOKE, headers=headers, json={"serial_hex": "1", "reason": "unspecified"})

    _assert_error(response, 401, "unauthenticated")
    _assert_error(revoke, 401, "unauthenticated")
    assert env.reviewer.audiences == []
    assert env.certificate_count() == env.extra["base"]


def test_rejected_token_401(env):
    response = env.sign(_csr()[0], token="unknown-token")

    body = _assert_error(response, 401, "unauthenticated")
    assert body["detail"] == "Token was not accepted."


def test_wrong_audience_401(env):
    env.reviewer.results["aud-token"] = TokenRejected("token audience mismatch")

    _assert_error(env.sign(_csr()[0], token="aud-token"), 401, "unauthenticated")


def test_non_service_account_403(env):
    env.reviewer.results["node-token"] = NotAServiceAccount("not a service account")

    _assert_error(env.sign(_csr()[0], token="node-token"), 403, "not_allowlisted")


def test_not_allowlisted_403(env):
    env.reviewer.add("default-token", "default", "default")

    body = _assert_error(env.sign(_csr()[0], token="default-token"), 403, "not_allowlisted")
    assert body["detail"] == "Workload is not on the allowlist."
    assert env.certificate_count() == env.extra["base"]


def test_review_unavailable_503(env):
    env.reviewer.results["down-token"] = TokenReviewUnavailable("down")

    _assert_error(env.sign(_csr()[0], token="down-token"), 503, "issuer_unavailable")


def test_disabled_or_no_trust_domain_503(env):
    env.setenv(WORKLOAD_ISSUANCE_ENABLED="false")
    body = _assert_error(env.sign(_csr()[0]), 503, "issuer_unavailable")
    assert body["detail"] == "Workload issuance is not enabled."
    _assert_error(env.revoke({"serial_hex": "1", "reason": "unspecified"}), 503, "issuer_unavailable")
    assert env.reviewer.audiences == []

    env.setenv(WORKLOAD_ISSUANCE_ENABLED="true", WORKLOAD_TRUST_DOMAIN="")
    _assert_error(env.sign(_csr()[0]), 503, "issuer_unavailable")


def _ed25519_csr() -> str:
    return _csr(ed25519.Ed25519PrivateKey.generate())[0]


@pytest.mark.parametrize(
    "case",
    ["not-json", "json-array", "missing-csr", "csr-not-string", "garbage-pem", "bad-signature", "ed25519"],
)
def test_bad_csr_400(env, case):
    before = env.certificate_count()
    kwargs: dict[str, Any]
    if case == "not-json":
        kwargs = {"content": b"this is not json", "headers": {"Content-Type": "application/json"}}
    elif case == "json-array":
        kwargs = {"json": ["csr_pem"]}
    elif case == "missing-csr":
        kwargs = {"json": {"other": "x"}}
    elif case == "csr-not-string":
        kwargs = {"json": {"csr_pem": 5}}
    elif case == "garbage-pem":
        kwargs = {"json": {"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"}}
    elif case == "bad-signature":
        kwargs = {"json": {"csr_pem": _tamper(_csr()[0])}}
    else:
        kwargs = {"json": {"csr_pem": _ed25519_csr()}}

    response = env.sign(**kwargs)

    _assert_error(response, 400, "invalid_csr")
    assert env.certificate_count() == before


def test_oversized_body_400(env):
    response = env.sign(content=b'{"csr_pem": "' + b"A" * 40000 + b'"}', headers={"Content-Type": "application/json"})

    _assert_error(response, 400, "invalid_csr")


def test_missing_issuer_503(env):
    csr_pem, _ = _csr()
    env.setenv(WORKLOAD_ISSUER_CA_NAME="")
    _assert_error(env.sign(csr_pem), 503, "issuer_unavailable")

    keyless = _keyless(env.db, name="Keyless Workload CA")
    env.setenv(WORKLOAD_ISSUER_CA_NAME=keyless.name)
    body = _assert_error(env.sign(csr_pem), 503, "issuer_unavailable")
    assert body["detail"] == "Workload issuer CA is not available."


def test_no_trust_anchor_503(env):
    env.root.status = CAStatusEnum.DISABLED
    env.db.commit()
    before = env.certificate_count()

    body = _assert_error(env.sign(_csr()[0]), 503, "issuer_unavailable")

    assert body["detail"] == "No trust anchor is configured for the workload issuer."
    assert env.certificate_count() == before


def test_issuer_that_cannot_sign_503(env):
    env.sub.not_after = env.sub.not_after.replace(year=2000)  # validity shorter than the leaf lifetime
    env.db.commit()
    before = env.certificate_count()

    body = _assert_error(env.sign(_csr()[0]), 503, "issuer_unavailable")

    assert body["detail"] == "Workload issuer CA cannot sign right now."
    assert env.certificate_count() == before


def test_rate_limit_429(env):
    env.setenv(WORKLOAD_SIGN_RATE_PER_HOUR="2")
    csr_pem, _ = _csr()

    assert env.sign(csr_pem).status_code == 201
    assert env.sign(csr_pem).status_code == 201
    limited = env.sign(csr_pem)

    body = _assert_error(limited, 429, "rate_limited")
    assert set(body) == {"error", "detail", "retry_after_s"}
    assert isinstance(body["retry_after_s"], int) and body["retry_after_s"] >= 1
    assert limited.headers["retry-after"] == str(body["retry_after_s"])
    assert env.sign(csr_pem, token=SERVER_TOKEN).status_code == 201


def test_revoke_own_200_and_listed_in_crl(env):
    env.client.get("/pki/issuing/crl.der")  # CRL number 1 exists before the revocation
    issued = env.issue()

    response = env.revoke({"serial_hex": issued["serial_hex"], "reason": "keyCompromise"})

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"revoked", "crl_number"}
    assert body["revoked"] is True
    assert body["crl_number"] >= 2
    crl = x509.load_der_x509_crl(env.client.get("/pki/issuing/crl.der").content)
    entry = crl.get_revoked_certificate_by_serial_number(int(issued["serial_hex"], 16))
    assert entry is not None
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.key_compromise
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == body["crl_number"]

    row = env.db.query(Certificate).filter(Certificate.serial_number == issued["serial_hex"]).one()
    revoked_at = row.revoked_at
    again = env.revoke({"serial_hex": issued["serial_hex"], "reason": "keyCompromise"})
    assert again.status_code == 200
    assert again.json() == body
    env.db.expire_all()
    assert row.revoked_at == revoked_at
    assert [r.details_json["result"] for r in env.audit_rows("WORKLOAD_REVOKE")] == ["revoked", "already_revoked"]


def test_revoke_other_identity_403_not_owner(env):
    issued = env.issue()

    response = env.revoke({"serial_hex": issued["serial_hex"], "reason": "superseded"}, token=SERVER_TOKEN)

    body = _assert_error(response, 403, "not_owner")
    assert body["detail"] == "Certificate belongs to another identity."
    row = env.db.query(Certificate).filter(Certificate.serial_number == issued["serial_hex"]).one()
    assert row.revoked_at is None


def test_revoke_unknown_404(env):
    body = _assert_error(env.revoke({"serial_hex": "abc123", "reason": "unspecified"}), 404, "not_found")
    assert body["detail"] == "Certificate not found."


def test_revoke_non_workload_cert_404(env):
    _, headers = _token(env.db)
    csr_pem, _ = _csr()
    general = env.client.post(
        "/api/v1/certificates/sign",
        headers=headers,
        json={"issuer_ca_id": env.root.id, "csr_pem": csr_pem, "validity_hours": 24, "usage_preset": "server_tls"},
    )
    assert general.status_code == 201
    serial = general.json()["serial_hex"]

    _assert_error(env.revoke({"serial_hex": serial, "reason": "unspecified"}), 404, "not_found")

    row = env.db.query(Certificate).filter(Certificate.serial_number == serial).one()
    assert row.revoked_at is None


@pytest.mark.parametrize(
    "body",
    [
        {"serial_hex": "xyz", "reason": "unspecified"},
        {"serial_hex": "", "reason": "unspecified"},
        {"serial_hex": "1" * 41, "reason": "unspecified"},
        {"serial_hex": 12, "reason": "unspecified"},
        {"serial_hex": "ab"},
        {"serial_hex": "ab", "reason": "affiliationChanged"},
        {"serial_hex": "ab", "reason": 3},
        ["ab"],
    ],
)
def test_revoke_bad_body_400_invalid_request(env, body):
    _assert_error(env.revoke(body), 400, "invalid_request")


def test_revoke_not_json_400(env):
    response = env.client.post(
        REVOKE,
        headers={"Authorization": f"Bearer {CLIENT_TOKEN}", "Content-Type": "application/json"},
        content=b"nope",
    )

    _assert_error(response, 400, "invalid_request")


def test_revoke_serial_normalized(env):
    issued = env.issue()
    messy = issued["serial_hex"].upper().rjust(40, "0")

    response = env.revoke({"serial_hex": messy, "reason": "cessationOfOperation"})

    assert response.status_code == 200
    row = env.db.query(Certificate).filter(Certificate.serial_number == issued["serial_hex"]).one()
    assert row.revoked_at is not None
    assert row.revocation_reason_code == "cessationOfOperation"


def test_audit_rows_for_allow_and_deny(env, caplog):
    caplog.set_level(logging.DEBUG)
    env.reviewer.add("default-token", "default", "default")
    csr_pem, _ = _csr()

    ok = env.sign(csr_pem)
    denied = env.sign(csr_pem, token="default-token")
    unauthenticated = env.client.post(SIGN, json={"csr_pem": csr_pem})

    assert (ok.status_code, denied.status_code, unauthenticated.status_code) == (201, 403, 401)
    rows = env.audit_rows("WORKLOAD_SIGN")
    assert len(rows) == 3
    allowed, deny, anon = rows
    assert allowed.actor_type == ActorType.WORKLOAD
    assert allowed.actor_id == CLIENT_ID
    assert allowed.status == AuditStatus.SUCCESS
    assert allowed.target_type == "certificate"
    assert allowed.target_id is not None
    assert allowed.details_json["result"] == "issued"
    assert allowed.details_json["spiffe_id"] == CLIENT_ID
    assert allowed.details_json["serial_hex"] == ok.json()["serial_hex"]
    assert deny.status == AuditStatus.FAILURE
    assert deny.actor_id is None
    assert deny.details_json["result"] == "not_allowlisted"
    assert deny.details_json["reason"] == "Workload is not on the allowlist."
    assert anon.actor_type == ActorType.WORKLOAD
    assert anon.actor_id is None
    assert anon.details_json["result"] == "unauthenticated"
    assert anon.details_json["spiffe_id"] is None
    assert allowed.ip_address is not None

    revoke_ok = env.revoke({"serial_hex": ok.json()["serial_hex"], "reason": "superseded"})
    assert revoke_ok.status_code == 200
    revoke_rows = env.audit_rows("WORKLOAD_REVOKE")
    assert revoke_rows[0].details_json["result"] == "revoked"
    assert revoke_rows[0].target_id == allowed.target_id

    secrets = (CLIENT_TOKEN, SERVER_TOKEN, "default-token")
    everything = " ".join(str(row.details_json) + str(row.actor_id) for row in env.db.query(AuditLog).all())
    for secret in secrets:
        assert secret not in everything
        assert secret not in caplog.text
    assert "workload request" in caplog.text


def test_error_shape_is_contract(env):
    env.setenv(WORKLOAD_SIGN_RATE_PER_HOUR="1")
    env.reviewer.add("default-token", "default", "default")
    env.reviewer.results["node-token"] = NotAServiceAccount("x")
    env.reviewer.results["down-token"] = TokenReviewUnavailable("x")
    csr_pem, _ = _csr()
    responses = [
        env.client.post(SIGN, json={"csr_pem": csr_pem}),
        env.sign(csr_pem, token="unknown-token"),
        env.sign(csr_pem, token="node-token"),
        env.sign(csr_pem, token="default-token"),
        env.sign(csr_pem, token="down-token"),
        env.sign(json=["x"]),
        env.sign(csr_pem, token=SERVER_TOKEN),
        env.sign(csr_pem, token=SERVER_TOKEN),
        env.revoke({"serial_hex": "zz", "reason": "unspecified"}),
        env.revoke({"serial_hex": "ab", "reason": "unspecified"}),
        env.revoke({"serial_hex": "ab", "reason": "unspecified"}, token="unknown-token"),
    ]

    shapes = [(r.status_code, sorted(r.json())) for r in responses]

    assert shapes == [
        (401, ["detail", "error"]),
        (401, ["detail", "error"]),
        (403, ["detail", "error"]),
        (403, ["detail", "error"]),
        (503, ["detail", "error"]),
        (400, ["detail", "error"]),
        (
            201,
            sorted(
                [
                    "spiffe_id",
                    "serial_hex",
                    "not_before",
                    "not_after",
                    "certificate_pem",
                    "chain_pem",
                    "trust_bundle_pem",
                ]
            ),
        ),
        (429, ["detail", "error", "retry_after_s"]),
        (400, ["detail", "error"]),
        (404, ["detail", "error"]),
        (401, ["detail", "error"]),
    ]


def test_routes_are_post_only(env):
    assert env.client.get(SIGN).status_code == 405
    assert env.client.get(REVOKE).status_code == 405


def _issue_via_api(env, issuer_id: str, token_headers: dict[str, str], uri_sans: list[str]):
    return env.client.post(
        "/api/v1/certificates",
        headers=token_headers,
        json={
            "issuer_ca_id": issuer_id,
            "common_name": "general.example.test",
            "dns_sans": ["general.example.test"],
            "uri_sans": uri_sans,
            "key_algorithm": "ECDSA",
            "curve": "P-256",
            "hash_algorithm": "SHA256",
            "validity_days": 30,
        },
    )


def test_reserved_issuer_blocks_general_issuance(env):
    _, headers = _token(env.db)
    message = "This CA is reserved for workload identities."

    blocked = _issue_via_api(env, env.sub.id, headers, [])
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == message
    issue_failures = env.audit_rows("ISSUE_CERT")
    assert [(row.status, row.details_json["reason"]) for row in issue_failures] == [(AuditStatus.FAILURE, message)]

    csr_pem, _ = _csr()
    sign_payload = {"issuer_ca_id": env.sub.id, "csr_pem": csr_pem, "validity_hours": 24, "usage_preset": "server_tls"}
    signed = env.client.post("/api/v1/certificates/sign", headers=headers, json=sign_payload)
    assert signed.status_code == 403
    assert signed.json()["detail"] == message
    failures = env.audit_rows("SIGN_CSR")
    assert len(failures) == 1
    assert failures[0].status == AuditStatus.FAILURE
    assert failures[0].details_json["reason"] == message

    assert _issue_via_api(env, env.root.id, headers, []).status_code == 201
    allowed = env.client.post(
        "/api/v1/certificates/sign", headers=headers, json={**sign_payload, "issuer_ca_id": env.root.id}
    )
    assert allowed.status_code == 201

    with pytest.raises(ValueError, match="reserved for workload identities"):
        issue_cert_from_ca(
            IssueFromCAConfig(
                issuer_ca_id=env.sub.id,
                common_name="ui.example.test",
                key_algorithm="ECDSA",
                curve="P-256",
                validity_days=30,
            ),
            env.sub,
            env.db,
        )


def test_general_paths_reject_workload_spiffe_ids(env):
    _, headers = _token(env.db)
    workload_uri = "spiffe://labca.example.test/ns/mtls-demo/sa/demo-client"
    other_uri = "spiffe://other.test/ns/mtls-demo/sa/demo-client"

    rejected = _issue_via_api(env, env.root.id, headers, [workload_uri])
    assert rejected.status_code == 403
    assert "issued only through workload attestation" in rejected.json()["detail"]
    assert [row.status for row in env.audit_rows("ISSUE_CERT")] == [AuditStatus.FAILURE]
    assert _issue_via_api(env, env.root.id, headers, [other_uri]).status_code == 201

    payload = {"issuer_ca_id": env.root.id, "validity_hours": 24, "usage_preset": "server_tls"}
    csr_bad, _ = _csr(uris=(workload_uri,))
    csr_ok, _ = _csr(uris=(other_uri,))
    bad = env.client.post("/api/v1/certificates/sign", headers=headers, json={**payload, "csr_pem": csr_bad})
    good = env.client.post("/api/v1/certificates/sign", headers=headers, json={**payload, "csr_pem": csr_ok})
    assert bad.status_code == 403
    assert good.status_code == 201
    assert env.db.query(Certificate).filter(Certificate.issued_to_spiffe_id.is_not(None)).count() == 0
