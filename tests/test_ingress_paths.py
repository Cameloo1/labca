"""Check the source Ingress manifests against the application routes.

Reads deploy/kustomize/**/*.yaml directly, no rendering needed.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from starlette.routing import Mount

from app.main import app
from app.security.route_class import RouteClass, classify
from tests.ingress_support import MACHINE_PROBES, ingress_paths, load_ingresses, path_matches

KUSTOMIZE_DIR = Path(__file__).resolve().parent.parent / "deploy" / "kustomize"
ADMIN_INGRESS_FILE = KUSTOMIZE_DIR / "components" / "admin-access" / "ingress.yaml"

# Probes and API docs are not served on the admin hostname.
NOT_ON_ADMIN_HOST = frozenset({"/health", "/ready", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"})

_PARAM = re.compile(r"\{[^}]*\}")


def _source_ingresses() -> list[dict[str, Any]]:
    return load_ingresses(sorted(KUSTOMIZE_DIR.rglob("*.yaml")))


def _by_name(name: str, docs: list[dict[str, Any]]) -> dict[str, Any]:
    found = [d for d in docs if d["metadata"]["name"] == name]
    assert len(found) == 1, name
    return found[0]


def _routes_to_labca(doc: dict[str, Any]) -> bool:
    return any(
        p["backend"]["service"]["name"] == "labca" for rule in doc["spec"]["rules"] for p in rule["http"]["paths"]
    )


def _walk(routes: list[Any], prefix: str = "") -> list[tuple[str, bool]]:
    """Flatten the route tree into (full path, is_mount), following included routers."""
    out: list[tuple[str, bool]] = []
    for route in routes:
        context = getattr(route, "include_context", None)
        if context is not None:
            out.extend(_walk(context.included_router.routes, prefix + context.prefix))
        elif isinstance(route, Mount):
            out.append((prefix + route.path, True))
        elif hasattr(route, "path"):
            # Other test modules register throwaway routes on the shared app object.
            if getattr(getattr(route, "endpoint", None), "__module__", "").startswith("tests."):
                continue
            out.append((prefix + route.path, False))
    return out


def _app_probes() -> list[tuple[str, str]]:
    """Return (route path, probe path) for every application route."""
    out: list[tuple[str, str]] = []
    for path, is_mount in _walk(list(app.routes)):
        probe = path + "/css/app.css" if is_mount else _PARAM.sub("1", path)
        out.append((path, probe))
    return out


@pytest.mark.parametrize(
    ("path_type", "ingress_path", "request_path", "expected"),
    [
        ("Exact", "/", "/", True),
        ("Exact", "/", "/cas", False),
        ("Exact", "/api", "/api", True),
        ("Exact", "/api", "/api/v1", False),
        ("Exact", "/api", "/api/", False),
        ("Prefix", "/", "/api/v1/workload/sign", True),
        ("Prefix", "/", "/", True),
        ("Prefix", "/cas", "/cas", True),
        ("Prefix", "/cas", "/cas/", True),
        ("Prefix", "/cas", "/cas/1/issue", True),
        ("Prefix", "/cas", "/cassette", False),
        ("Prefix", "/cas/", "/cas", True),
        ("Prefix", "/cas/", "/cas/1/issue", True),
        ("Prefix", "/cas/", "/cassette", False),
        ("Prefix", "/api", "/api/v1", True),
        ("Prefix", "/api", "/apix", False),
    ],
)
def test_path_matches_semantics(path_type: str, ingress_path: str, request_path: str, expected: bool) -> None:
    assert path_matches(path_type, ingress_path, request_path) is expected


def test_path_matches_rejects_other_path_types() -> None:
    with pytest.raises(ValueError, match="ImplementationSpecific"):
        path_matches("ImplementationSpecific", "/", "/")


def test_no_source_ingress_routes_machine_paths() -> None:
    docs = _source_ingresses()
    names = {d["metadata"]["name"] for d in docs}
    assert {"labca-pki", "labca-status", "labca-admin"} <= names
    assert len(docs) >= 3
    machine_routes = [probe for route, probe in _app_probes() if classify(route) is RouteClass.MACHINE]
    probes = list(MACHINE_PROBES) + machine_routes
    for doc in docs:
        name = doc["metadata"]["name"]
        for _host, path_type, path in ingress_paths(doc):
            assert path_type in ("Exact", "Prefix"), f"{name}: {path} has pathType {path_type}"
        # An Ingress whose backend is another service cannot reach LabCA, so the
        # LabCA API exposure check applies to Ingresses that route to the labca service.
        if not _routes_to_labca(doc):
            continue
        for _host, path_type, path in ingress_paths(doc):
            for probe in probes:
                assert not path_matches(path_type, path, probe), f"{name}: {path_type} {path} matches {probe}"


def test_admin_ingress_covers_admin_routes() -> None:
    admin = _by_name("labca-admin", load_ingresses([ADMIN_INGRESS_FILE]))
    paths = ingress_paths(admin)
    checked: set[str] = set()
    for route_path, probe in _app_probes():
        if route_path in NOT_ON_ADMIN_HOST:
            continue
        checked.add(route_path)
        matched = [(t, p) for _h, t, p in paths if path_matches(t, p, probe)]
        if classify(probe) is RouteClass.MACHINE:
            assert not matched, f"machine route {route_path} ({probe}) is routed by {matched}"
        else:
            assert matched, f"route {route_path} ({probe}) is not routed by labca-admin"
    assert checked
    assert {"/", "/api", "/cas", "/setup"} <= checked


def test_public_ingress_routes_only_pki() -> None:
    pki = _by_name("labca-pki", _source_ingresses())
    rules = pki["spec"]["rules"]
    assert len(rules) == 1
    entries = rules[0]["http"]["paths"]
    assert len(entries) == 1
    entry = entries[0]
    assert (entry["pathType"], entry["path"]) == ("Prefix", "/pki")
    assert entry["backend"]["service"]["name"] == "labca"
    assert entry["backend"]["service"]["port"]["number"] == 8000
