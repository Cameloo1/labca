"""Contract checks on the rendered Kubernetes manifests.

These tests read .cache/rendered/*.yaml, produced by scripts/render-manifests.sh.
They are deselected from the normal suite and run by scripts/check-manifests.sh.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.ingress_support import MACHINE_PROBES, ingress_paths, path_matches

pytestmark = pytest.mark.manifests

RENDERED_DIR = Path(__file__).resolve().parent.parent / ".cache" / "rendered"
RENDERED_FILES = ["ci.yaml", "prod.yaml", "prod-access.yaml"]

# (cpu request, cpu limit, memory request, memory limit) by container name.
RESOURCES = {
    "labca": ("50m", "500m", "160Mi", "512Mi"),
    "migrate": ("50m", "500m", "160Mi", "512Mi"),
    "demo-server": ("10m", "200m", "24Mi", "96Mi"),
    "demo-client": ("10m", "200m", "24Mi", "96Mi"),
    "mtls-verifier": ("20m", "200m", "32Mi", "128Mi"),
    "cloudflared": ("20m", "200m", "48Mi", "192Mi"),
    "backup": ("20m", "200m", "64Mi", "192Mi"),
    "prune": ("20m", "200m", "64Mi", "192Mi"),
}
# Workload name -> UID. labca pods use 10001, the Go and cloudflared pods 65532.
UIDS = {"labca": 10001, "labca-backup": 10001}
DEFAULT_UID = 65532

BANNED_POD_KEYS = ("hostNetwork", "hostPID", "hostIPC")


def _load(name: str) -> list[dict[str, Any]]:
    path = RENDERED_DIR / name
    if not path.is_file():
        pytest.fail("run scripts/render-manifests.sh .cache/rendered first")
    docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    return docs


@pytest.fixture(params=RENDERED_FILES)
def docs(request: pytest.FixtureRequest) -> list[dict[str, Any]]:
    return _load(request.param)


def _pod_specs(docs: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for d in docs:
        kind = d.get("kind")
        name = d["metadata"]["name"]
        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            out.append((name, d["spec"]["template"]["spec"]))
        elif kind == "CronJob":
            out.append((name, d["spec"]["jobTemplate"]["spec"]["template"]["spec"]))
        elif kind == "Job":
            out.append((name, d["spec"]["template"]["spec"]))
        elif kind == "Pod":
            out.append((name, d["spec"]))
    return out


def _walk(node: Any):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def test_rendered_files_have_objects(docs: list[dict[str, Any]]) -> None:
    assert len(docs) > 20
    assert _pod_specs(docs)


def test_pod_security_context(docs: list[dict[str, Any]]) -> None:
    for name, spec in _pod_specs(docs):
        uid = UIDS.get(name, DEFAULT_UID)
        assert spec["automountServiceAccountToken"] is False, name
        assert spec["enableServiceLinks"] is False, name
        sc = spec["securityContext"]
        assert sc["runAsNonRoot"] is True, name
        assert sc["runAsUser"] == uid, name
        assert sc["runAsGroup"] == uid, name
        assert sc["fsGroup"] == uid, name
        assert sc["seccompProfile"] == {"type": "RuntimeDefault"}, name
        if uid == 10001:
            assert sc["fsGroupChangePolicy"] == "OnRootMismatch", name


def test_container_security_and_resources(docs: list[dict[str, Any]]) -> None:
    seen = set()
    for name, spec in _pod_specs(docs):
        containers = spec.get("initContainers", []) + spec["containers"]
        assert containers, name
        for c in containers:
            where = f"{name}/{c['name']}"
            seen.add(c["name"])
            sc = c["securityContext"]
            assert sc["readOnlyRootFilesystem"] is True, where
            assert sc["allowPrivilegeEscalation"] is False, where
            assert sc["runAsNonRoot"] is True, where
            assert sc["capabilities"] == {"drop": ["ALL"]}, where
            assert c["imagePullPolicy"] == "IfNotPresent", where
            cpu_req, cpu_lim, mem_req, mem_lim = RESOURCES[c["name"]]
            res = c["resources"]
            assert res["requests"] == {"cpu": cpu_req, "memory": mem_req}, where
            assert res["limits"] == {"cpu": cpu_lim, "memory": mem_lim}, where
    assert {"labca", "migrate", "demo-server", "demo-client", "mtls-verifier", "backup", "prune"} <= seen


def test_no_latest_tag(docs: list[dict[str, Any]]) -> None:
    for name, spec in _pod_specs(docs):
        for c in spec.get("initContainers", []) + spec["containers"]:
            image = c["image"].split("@", 1)[0]
            tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else "latest"
            assert tag != "latest", f"{name}/{c['name']}"


def test_no_secret_objects(docs: list[dict[str, Any]]) -> None:
    assert [d["metadata"]["name"] for d in docs if d["kind"] == "Secret"] == []


def test_ingress_never_routes_api(docs: list[dict[str, Any]]) -> None:
    ingresses = [d for d in docs if d["kind"] == "Ingress"]
    assert ingresses
    for ing in ingresses:
        name = ing["metadata"]["name"]
        to_labca = any(
            p["backend"]["service"]["name"] == "labca" for r in ing["spec"]["rules"] for p in r["http"]["paths"]
        )
        for _host, path_type, path in ingress_paths(ing):
            assert path_type in ("Exact", "Prefix"), f"{name}: {path} has pathType {path_type}"
            assert not path.startswith("/api/"), f"{name}: {path}"
            if path_type == "Prefix":
                assert path != "/api", name
            if path == "/api":
                assert path_type == "Exact" and name == "labca-admin", name
            # The labca-status Ingress routes to the demo server, not to LabCA, so only
            # Ingresses with a labca backend are checked against the machine probes.
            if to_labca:
                for probe in MACHINE_PROBES:
                    assert not path_matches(path_type, path, probe), f"{name}: {path_type} {path} matches {probe}"


def test_admin_ingress_paths_rendered() -> None:
    docs = _load("prod-access.yaml")
    admin = [d for d in docs if d["kind"] == "Ingress" and d["metadata"]["name"] == "labca-admin"]
    assert len(admin) == 1
    rules = admin[0]["spec"]["rules"]
    assert len(rules) == 1
    assert rules[0]["host"] == "labca-admin.camelon.app"
    expected = [("Exact", "/"), ("Exact", "/api")] + [
        ("Prefix", p)
        for p in (
            "/audit",
            "/cas",
            "/certificates",
            "/help",
            "/notifications",
            "/pki",
            "/profiles",
            "/quick-cert",
            "/settings",
            "/setup",
            "/static",
        )
    ]
    entries = rules[0]["http"]["paths"]
    assert [(e["pathType"], e["path"]) for e in entries] == expected
    for e in entries:
        assert e["backend"]["service"] == {"name": "labca", "port": {"number": 8000}}


def test_default_deny_in_every_namespace_with_pods(docs: list[dict[str, Any]]) -> None:
    pod_namespaces = {
        d["metadata"]["namespace"]
        for d in docs
        if d["kind"] in ("Deployment", "CronJob", "Job", "StatefulSet", "DaemonSet")
    }
    assert pod_namespaces
    deny = {
        d["metadata"]["namespace"]
        for d in docs
        if d["kind"] == "NetworkPolicy"
        and d["metadata"]["name"] == "default-deny"
        and d["spec"]["podSelector"] == {}
        and sorted(d["spec"]["policyTypes"]) == ["Egress", "Ingress"]
        and not d["spec"].get("ingress")
        and not d["spec"].get("egress")
    }
    assert pod_namespaces <= deny


def test_no_forbidden_pod_features(docs: list[dict[str, Any]]) -> None:
    for name, spec in _pod_specs(docs):
        for key in BANNED_POD_KEYS:
            assert not spec.get(key), f"{name}: {key}"
        for vol in spec.get("volumes", []):
            assert "hostPath" not in vol, name
        for c in spec.get("initContainers", []) + spec["containers"]:
            assert not c["securityContext"].get("privileged"), name
    for d in docs:
        for node in _walk(d):
            assert "subPath" not in node, d["metadata"]["name"]
            assert "subPathExpr" not in node, d["metadata"]["name"]


def test_no_exposed_service_types(docs: list[dict[str, Any]]) -> None:
    services = [d for d in docs if d["kind"] == "Service"]
    assert services
    for s in services:
        assert s["spec"].get("type", "ClusterIP") not in ("NodePort", "LoadBalancer"), s["metadata"]["name"]


def test_forwarded_allow_ips_is_never_wildcard(docs: list[dict[str, Any]]) -> None:
    cms = [d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"].startswith("labca-config")]
    assert len(cms) == 1
    value = cms[0]["data"]["FORWARDED_ALLOW_IPS"]
    assert value != "*"
    assert "*" not in value
    assert value == "10.42.0.0/16"


def test_ci_has_no_cloudflared_workload() -> None:
    ci = _load("ci.yaml")
    assert [d for d in ci if d["kind"] == "Deployment" and d["metadata"]["name"] == "cloudflared"] == []
    prod = _load("prod.yaml")
    assert [d for d in prod if d["kind"] == "Deployment" and d["metadata"]["name"] == "cloudflared"]


def test_admin_ingress_only_with_component() -> None:
    def admin(docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [d for d in docs if d["kind"] == "Ingress" and d["metadata"]["name"] == "labca-admin"]

    assert admin(_load("ci.yaml")) == []
    assert admin(_load("prod.yaml")) == []
    assert len(admin(_load("prod-access.yaml"))) == 1


def test_rendered_missing_file_fails_loudly() -> None:
    with pytest.raises(pytest.fail.Exception, match="run scripts/render-manifests.sh"):
        _load("does-not-exist.yaml")
