"""Helpers for checking Kubernetes Ingress paths against request paths."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import yaml

MACHINE_PROBES: tuple[str, ...] = (
    "/api/v1",
    "/api/v1/",
    "/api/v1/workload/sign",
    "/api/v1/workload/revoke",
    "/api/v1/certificates/sign",
    "/api/v1/certificates/1/revoke",
    "/api/v1/certificates/1",
)


def _elements(path: str) -> list[str]:
    return [e for e in path.split("/") if e]


def path_matches(path_type: str, ingress_path: str, request_path: str) -> bool:
    """Apply the Kubernetes Ingress path matching rules for Exact and Prefix."""
    if path_type == "Exact":
        return request_path == ingress_path
    if path_type == "Prefix":
        want = _elements(ingress_path)
        got = _elements(request_path)
        return got[: len(want)] == want
    raise ValueError(f"unsupported pathType: {path_type}")


def ingress_paths(doc: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return (host, pathType, path) for every path of every rule of one Ingress."""
    out: list[tuple[str, str, str]] = []
    for rule in doc["spec"].get("rules", []):
        host = rule.get("host", "")
        for p in rule["http"]["paths"]:
            out.append((host, p.get("pathType", ""), p["path"]))
    return out


def load_ingresses(paths: Iterable[Path]) -> list[dict[str, Any]]:
    """Return every document with kind Ingress from the given YAML files."""
    found: list[dict[str, Any]] = []
    for path in paths:
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc and doc.get("kind") == "Ingress":
                found.append(doc)
    return found
