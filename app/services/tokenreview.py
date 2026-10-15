"""Verify Kubernetes ServiceAccount tokens with the TokenReview API.

Neither the caller's token nor LabCA's own token is ever logged, stored, or
placed in an exception message.
"""

from __future__ import annotations

import os
import re
import ssl
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Optional, Protocol

import httpx

from app.config import get_settings

SA_USERNAME_RE = re.compile(
    r"^system:serviceaccount:([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?):([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?)$"
)


@dataclass(frozen=True)
class ReviewedIdentity:
    namespace: str
    service_account: str
    username: str  # "system:serviceaccount:<ns>:<sa>"


class TokenReviewError(Exception):
    """Base class for token review failures."""


class TokenRejected(TokenReviewError):
    """The token is not valid for this audience."""


class NotAServiceAccount(TokenReviewError):
    """The token is valid but does not belong to a ServiceAccount."""


class TokenReviewUnavailable(TokenReviewError):
    """The Kubernetes API could not give a verdict."""


class TokenReviewer(Protocol):
    def review(self, token: str, audience: str) -> ReviewedIdentity: ...


class InClusterTokenReviewer:
    def __init__(
        self,
        *,
        host: Optional[str] = None,
        port: Optional[str] = None,
        sa_token_file: str,
        ca_file: str,
        timeout: float = 5.0,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self._host = host
        self._port = port
        self._sa_token_file = sa_token_file
        self._ca_file = ca_file
        self._timeout = timeout
        self._transport = transport

    def __repr__(self) -> str:
        return "InClusterTokenReviewer()"

    def _url(self) -> str:
        host = self._host if self._host is not None else os.environ.get("KUBERNETES_SERVICE_HOST")
        port = self._port if self._port is not None else os.environ.get("KUBERNETES_SERVICE_PORT")
        if not host or not port:
            raise TokenReviewUnavailable("Kubernetes API is not configured.")
        if ":" in host:
            host = f"[{host}]"
        return f"https://{host}:{port}/apis/authentication.k8s.io/v1/tokenreviews"

    def _own_token(self) -> str:
        try:
            with open(self._sa_token_file, encoding="utf-8") as handle:
                own = handle.read().strip()
        except (OSError, UnicodeDecodeError):
            raise TokenReviewUnavailable("LabCA service account token is unreadable.") from None
        if not own:
            raise TokenReviewUnavailable("LabCA service account token is empty.")
        return own

    def review(self, token: str, audience: str) -> ReviewedIdentity:
        url = self._url()
        own_token = self._own_token()
        try:
            context = ssl.create_default_context(cafile=self._ca_file)
        except (OSError, ssl.SSLError):
            raise TokenReviewUnavailable("Kubernetes CA bundle is unreadable.") from None

        body = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {"token": token, "audiences": [audience]},
        }
        headers = {"Authorization": f"Bearer {own_token}", "Content-Type": "application/json"}
        try:
            # trust_env=False: proxy variables must never route either token through a proxy.
            with httpx.Client(
                verify=context,
                timeout=self._timeout,
                transport=self._transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.post(url, headers=headers, json=body)
        except httpx.HTTPError:
            raise TokenReviewUnavailable("Kubernetes API request failed.") from None
        if response.status_code not in (200, 201):
            raise TokenReviewUnavailable("Kubernetes API returned an unexpected status.")
        try:
            payload: Any = response.json()
        except ValueError:
            raise TokenReviewUnavailable("Kubernetes API returned invalid JSON.") from None
        if not isinstance(payload, dict):
            raise TokenReviewUnavailable("Kubernetes API returned an unexpected body.")

        status = payload.get("status")
        if not isinstance(status, dict):
            status = {}
        if status.get("authenticated") is not True:
            raise TokenRejected("token not authenticated")
        audiences = status.get("audiences")
        if not isinstance(audiences, list) or audience not in audiences:
            raise TokenRejected("token audience mismatch")
        user = status.get("user")
        username = user.get("username") if isinstance(user, dict) else None
        match = SA_USERNAME_RE.fullmatch(username) if isinstance(username, str) else None
        if match is None or not isinstance(username, str):
            raise NotAServiceAccount("not a service account")
        return ReviewedIdentity(namespace=match.group(1), service_account=match.group(3), username=username)


@lru_cache()
def get_token_reviewer() -> TokenReviewer:
    settings = get_settings()
    return InClusterTokenReviewer(
        host=os.environ.get("KUBERNETES_SERVICE_HOST"),
        port=os.environ.get("KUBERNETES_SERVICE_PORT"),
        sa_token_file=settings.KUBE_SA_TOKEN_FILE,
        ca_file=settings.KUBE_CA_FILE,
    )
