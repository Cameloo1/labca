"""Workload identity helpers: SPIFFE IDs, allowlist, rate limiting, trust bundle, reserved issuer."""

from __future__ import annotations

import math
import threading
import time
from typing import Callable, Optional, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session

from app.config import get_settings, parse_allowlist
from app.models import CertificateAuthority
from app.services import pki_service

__all__ = [
    "RateLimiter",
    "derived_dns_sans",
    "get_rate_limiter",
    "is_reserved_for_workloads",
    "parse_allowlist",
    "reject_workload_trust_domain_uris",
    "reset_rate_limiter",
    "spiffe_id_for",
    "workload_trust_bundle",
]

_IDLE_SECONDS = 3600.0
_SWEEP_INTERVAL_SECONDS = 60.0


def spiffe_id_for(trust_domain: str, namespace: str, service_account: str) -> str:
    return f"spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"


def derived_dns_sans(namespace: str, service_account: str) -> list[str]:
    return [f"{service_account}.{namespace}.svc", f"{service_account}.{namespace}.svc.cluster.local"]


class RateLimiter:
    """Token bucket per key: capacity per_hour, refilled evenly over an hour, starting full."""

    def __init__(self, per_hour: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.per_hour = per_hour
        self._clock = clock
        self._rate = per_hour / 3600.0
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last seen)
        self._last_sweep = clock()

    def acquire(self, key: str) -> Optional[int]:
        """Return None when allowed, otherwise the seconds to wait (at least 1)."""
        with self._lock:
            now = self._clock()
            self._sweep(now)
            tokens, last = self._buckets.get(key, (float(self.per_hour), now))
            tokens = min(float(self.per_hour), tokens + max(0.0, now - last) * self._rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return None
            self._buckets[key] = (tokens, now)
            return max(1, math.ceil((1.0 - tokens) / self._rate))

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < _SWEEP_INTERVAL_SECONDS:
            return
        self._last_sweep = now
        stale = [key for key, (_, last) in self._buckets.items() if now - last > _IDLE_SECONDS]
        for key in stale:
            del self._buckets[key]


_limiter: Optional[RateLimiter] = None
_limiter_lock = threading.Lock()


def get_rate_limiter() -> RateLimiter:
    global _limiter
    per_hour = get_settings().WORKLOAD_SIGN_RATE_PER_HOUR
    with _limiter_lock:
        if _limiter is None or _limiter.per_hour != per_hour:
            _limiter = RateLimiter(per_hour)
        return _limiter


def reset_rate_limiter() -> None:
    global _limiter
    with _limiter_lock:
        _limiter = None


def workload_trust_bundle(db: Session, issuer: CertificateAuthority) -> list[x509.Certificate]:
    top = pki_service.chain_certificates(issuer, db)[-1]
    if pki_service.is_self_signed(top):
        return [top]
    bundle: list[x509.Certificate] = []
    for root in pki_service.trust_bundle_certificates(db):
        try:
            top.verify_directly_issued_by(root)
        except (ValueError, TypeError, InvalidSignature):
            continue
        bundle.append(root)
    return bundle


def is_reserved_for_workloads(db: Session, ca: CertificateAuthority) -> bool:
    settings = get_settings()
    if not settings.WORKLOAD_ISSUANCE_ENABLED:
        return False
    issuer = pki_service.resolve_workload_issuer(db, settings)
    return issuer is not None and issuer.id == ca.id


def reject_workload_trust_domain_uris(uri_sans: Sequence[str]) -> None:
    trust_domain = get_settings().WORKLOAD_TRUST_DOMAIN
    if not trust_domain:
        return
    prefix = f"spiffe://{trust_domain}/".lower()
    for uri in uri_sans:
        if uri[: len(prefix)].lower() == prefix:
            raise ValueError("SPIFFE IDs in the workload trust domain are issued only through workload attestation.")
