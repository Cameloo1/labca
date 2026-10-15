"""Classify request paths as PUBLIC, MACHINE, or ADMIN."""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping, Optional


class RouteClass(str, Enum):
    PUBLIC = "PUBLIC"
    MACHINE = "MACHINE"
    ADMIN = "ADMIN"


_PUBLIC_EXACT = frozenset({"/health", "/ready", "/pki", "/static"})
_PUBLIC_PREFIXES = ("/pki/", "/static/")
_MACHINE_EXACT = frozenset({"/api/v1"})
_MACHINE_PREFIXES = ("/api/v1/",)


def _is_suspicious(path: str, raw_path: Optional[bytes]) -> bool:
    if "\\" in path or "//" in path or "/../" in path or "/./" in path:
        return True
    if path.endswith("/..") or path.endswith("/."):
        return True
    if raw_path is not None:
        lowered = raw_path.lower()
        if b"%2e" in lowered or b"%2f" in lowered or b"%5c" in lowered:
            return True
    return False


def classify(path: str, raw_path: Optional[bytes] = None) -> RouteClass:
    """Return the route class for an ASGI path.

    Paths that look like prefix tricks (dot segments, double slashes, encoded dots
    or slashes, backslashes) are always ADMIN so they get the strictest checks.
    """
    if _is_suspicious(path, raw_path):
        return RouteClass.ADMIN
    if path in _PUBLIC_EXACT or path.startswith(_PUBLIC_PREFIXES):
        return RouteClass.PUBLIC
    if path in _MACHINE_EXACT or path.startswith(_MACHINE_PREFIXES):
        return RouteClass.MACHINE
    return RouteClass.ADMIN


def classify_scope(scope: Mapping[str, Any]) -> RouteClass:
    return classify(scope.get("path", ""), scope.get("raw_path"))
