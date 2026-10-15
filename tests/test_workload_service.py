"""Tests for workload_service helpers and the workload settings."""

from __future__ import annotations

import pytest
from cryptography import x509
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.models import CAStatusEnum
from app.services.workload_service import (
    RateLimiter,
    derived_dns_sans,
    get_rate_limiter,
    is_reserved_for_workloads,
    parse_allowlist,
    reject_workload_trust_domain_uris,
    reset_rate_limiter,
    spiffe_id_for,
    workload_trust_bundle,
)
from tests.test_pki_routes import _keyless, _root, _sub


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _settings(monkeypatch, **values: str) -> Settings:
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return Settings(_env_file=None)  # type: ignore[call-arg]  # pydantic-settings accepts _env_file at runtime


def test_parse_allowlist_valid():
    assert parse_allowlist("") == frozenset()
    assert parse_allowlist(" , ,") == frozenset()
    assert parse_allowlist("mtls-demo/demo-server, mtls-demo/demo-client ,mtls-demo/demo-server") == frozenset(
        {("mtls-demo", "demo-server"), ("mtls-demo", "demo-client")}
    )


@pytest.mark.parametrize("value", ["onlyname", "a/b/c", "/sa", "ns/", "ns/sa,bad", " / "])
def test_parse_allowlist_invalid(value):
    with pytest.raises(ValueError):
        parse_allowlist(value)


def test_spiffe_id_and_dns_sans():
    assert spiffe_id_for("labca.example.test", "mtls-demo", "demo-client") == (
        "spiffe://labca.example.test/ns/mtls-demo/sa/demo-client"
    )
    assert derived_dns_sans("mtls-demo", "demo-client") == [
        "demo-client.mtls-demo.svc",
        "demo-client.mtls-demo.svc.cluster.local",
    ]


def test_rate_limiter_capacity_and_refill():
    clock = FakeClock()
    limiter = RateLimiter(2, clock)

    assert limiter.acquire("a") is None
    assert limiter.acquire("a") is None
    assert limiter.acquire("a") == 1800  # one token at 2 per hour takes 1800 seconds

    clock.now += 900
    assert limiter.acquire("a") == 900  # half a token back, half an interval to wait
    clock.now += 900
    assert limiter.acquire("a") is None
    assert limiter.acquire("a") == 1800


def test_rate_limiter_retry_after_is_at_least_one_second():
    clock = FakeClock()
    limiter = RateLimiter(3600, clock)
    for _ in range(3600):
        assert limiter.acquire("a") is None
    clock.now += 0.25

    assert limiter.acquire("a") == 1


def test_rate_limiter_caps_at_capacity():
    clock = FakeClock()
    limiter = RateLimiter(2, clock)
    clock.now += 100000
    assert limiter.acquire("a") is None
    assert limiter.acquire("a") is None
    assert limiter.acquire("a") is not None


def test_rate_limiter_isolates_keys():
    limiter = RateLimiter(1, FakeClock())
    assert limiter.acquire("a") is None
    assert limiter.acquire("a") is not None
    assert limiter.acquire("b") is None


def test_rate_limiter_drops_idle_keys():
    clock = FakeClock()
    limiter = RateLimiter(5, clock)
    limiter.acquire("idle")
    clock.now += 1800
    limiter.acquire("recent")
    clock.now += 1900  # "idle" has now been quiet for 3700 seconds, "recent" for 1900

    limiter.acquire("trigger")

    assert set(limiter._buckets) == {"recent", "trigger"}


def test_get_rate_limiter_follows_setting(monkeypatch):
    reset_rate_limiter()
    _settings(monkeypatch, WORKLOAD_SIGN_RATE_PER_HOUR="5")
    first = get_rate_limiter()
    assert first.per_hour == 5
    assert get_rate_limiter() is first

    _settings(monkeypatch, WORKLOAD_SIGN_RATE_PER_HOUR="7")
    second = get_rate_limiter()
    assert second is not first
    assert second.per_hour == 7
    reset_rate_limiter()
    assert get_rate_limiter() is not second


def test_trust_bundle_for_self_signed_issuer(db_session):
    root = _root(db_session)

    bundle = workload_trust_bundle(db_session, root)

    assert bundle == [x509.load_pem_x509_certificate(root.cert_pem.encode())]


def test_trust_bundle_for_sub_ca_with_root_present(db_session):
    root = _root(db_session, name="Bundle Root")
    _root(db_session, name="Unrelated Root")
    sub = _sub(db_session, root)

    bundle = workload_trust_bundle(db_session, sub)

    assert len(bundle) == 1
    assert bundle[0] == x509.load_pem_x509_certificate(root.cert_pem.encode())


def test_trust_bundle_empty_when_root_absent(db_session):
    root = _root(db_session, name="Gone Root")
    sub = _sub(db_session, root)
    root.status = CAStatusEnum.DISABLED
    db_session.commit()

    assert workload_trust_bundle(db_session, sub) == []


def test_reject_workload_trust_domain_uris(monkeypatch):
    _settings(monkeypatch)
    reject_workload_trust_domain_uris(["spiffe://labca.example.test/ns/a/sa/b"])  # no trust domain set: allowed

    _settings(monkeypatch, WORKLOAD_TRUST_DOMAIN="labca.example.test")
    for blocked in (
        "spiffe://labca.example.test/ns/a/sa/b",
        "SPIFFE://LABCA.EXAMPLE.TEST/ns/a/sa/b",
    ):
        with pytest.raises(ValueError, match="issued only through workload attestation"):
            reject_workload_trust_domain_uris(["https://ok.example.test/x", blocked])
    reject_workload_trust_domain_uris(
        ["spiffe://other.test/ns/a/sa/b", "spiffe://labca.example.test.evil/x", "https://labca.example.test/"]
    )


def test_is_reserved_for_workloads(db_session, monkeypatch):
    root = _root(db_session, name="Reserved Root")
    sub = _sub(db_session, root, name="Reserved Sub")
    keyless = _keyless(db_session)

    _settings(monkeypatch, WORKLOAD_ISSUER_CA_NAME="Reserved Sub")
    assert is_reserved_for_workloads(db_session, sub) is False  # issuance disabled

    _settings(monkeypatch, WORKLOAD_ISSUER_CA_NAME="Reserved Sub", WORKLOAD_ISSUANCE_ENABLED="true")
    assert is_reserved_for_workloads(db_session, sub) is True
    assert is_reserved_for_workloads(db_session, root) is False
    assert is_reserved_for_workloads(db_session, keyless) is False


def test_settings_defaults(monkeypatch):
    for name in (
        "WORKLOAD_ISSUANCE_ENABLED",
        "WORKLOAD_TRUST_DOMAIN",
        "WORKLOAD_TOKEN_AUDIENCE",
        "WORKLOAD_ALLOWLIST",
        "WORKLOAD_CERT_TTL_MINUTES",
        "WORKLOAD_SIGN_RATE_PER_HOUR",
        "KUBE_SA_TOKEN_FILE",
        "KUBE_CA_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = _settings(monkeypatch)

    assert settings.WORKLOAD_ISSUANCE_ENABLED is False
    assert settings.WORKLOAD_TRUST_DOMAIN is None
    assert settings.WORKLOAD_TOKEN_AUDIENCE == "labca"
    assert settings.WORKLOAD_ALLOWLIST == ""
    assert settings.WORKLOAD_CERT_TTL_MINUTES == 60
    assert settings.WORKLOAD_SIGN_RATE_PER_HOUR == 30
    assert settings.KUBE_SA_TOKEN_FILE == "/var/run/secrets/kubernetes.io/serviceaccount/token"
    assert settings.KUBE_CA_FILE == "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def test_settings_trust_domain_validation(monkeypatch):
    assert _settings(monkeypatch, WORKLOAD_TRUST_DOMAIN="").WORKLOAD_TRUST_DOMAIN is None
    assert _settings(monkeypatch, WORKLOAD_TRUST_DOMAIN="labca.example-1.test").WORKLOAD_TRUST_DOMAIN == (
        "labca.example-1.test"
    )
    for bad in ("Upper.test", "has space", "a/b", "spiffe://x", "x" * 256):
        with pytest.raises(ValidationError):
            _settings(monkeypatch, WORKLOAD_TRUST_DOMAIN=bad)


def test_settings_allowlist_validation(monkeypatch):
    assert _settings(monkeypatch, WORKLOAD_ALLOWLIST="a/b, c/d").WORKLOAD_ALLOWLIST == "a/b, c/d"
    for bad in ("nonsense", "a/b/c", "a/"):
        with pytest.raises(ValidationError):
            _settings(monkeypatch, WORKLOAD_ALLOWLIST=bad)


def test_settings_numeric_bounds(monkeypatch):
    for name, bad in (
        ("WORKLOAD_CERT_TTL_MINUTES", "4"),
        ("WORKLOAD_CERT_TTL_MINUTES", "1441"),
        ("WORKLOAD_SIGN_RATE_PER_HOUR", "0"),
        ("WORKLOAD_SIGN_RATE_PER_HOUR", "3601"),
        ("WORKLOAD_TOKEN_AUDIENCE", ""),
    ):
        with pytest.raises(ValidationError):
            _settings(monkeypatch, **{name: bad})
        monkeypatch.delenv(name)
