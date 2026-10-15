"""Per-token issuance and revocation policy checks."""

from __future__ import annotations

from typing import Optional, Sequence

from app.models import ApiToken, Certificate
from app.schemas import TokenPolicy


class PolicyViolation(Exception):
    """Raised when a request is not allowed by the token policy; ``str(exc)`` is client-safe."""


def policy_for(token: ApiToken) -> Optional[TokenPolicy]:
    """Return the token policy, or None for legacy tokens (unrestricted issuance)."""
    if token.policy_json is None:
        return None
    return TokenPolicy.model_validate(token.policy_json)


def check_issuance(
    policy: Optional[TokenPolicy],
    *,
    dns_sans: Sequence[str],
    ip_sans: Sequence[str],
    uri_sans: Sequence[str],
    validity_hours: int,
) -> None:
    if policy is None:
        return
    for raw in dns_sans:
        name = raw.lower().rstrip(".")
        if not any(name == suffix or name.endswith("." + suffix) for suffix in policy.allowed_dns_suffixes):
            raise PolicyViolation(f"DNS SAN '{name}' is not allowed by the token policy.")
    if ip_sans:
        raise PolicyViolation("IP SANs are not allowed by the token policy.")
    for uri in uri_sans:
        if not any(uri.startswith(prefix) for prefix in policy.allowed_uri_prefixes):
            raise PolicyViolation(f"URI SAN '{uri}' is not allowed by the token policy.")
    if validity_hours > policy.max_validity_hours:
        raise PolicyViolation(
            f"Requested validity of {validity_hours} hours exceeds the token policy maximum "
            f"of {policy.max_validity_hours} hours."
        )


def can_revoke(token: ApiToken, certificate: Certificate) -> bool:
    if certificate.issued_by_token_id == token.id:
        return True
    policy = policy_for(token)
    return policy is not None and policy.revoke_any
