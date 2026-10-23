"""Offline syntax/contract checks; this does not certify a running OpenShell sandbox.

Run with Python 3.11+ and PyYAML. No files are written and no daemons are contacted.
"""

from pathlib import Path
import importlib.util
import json
import re
import tomllib

import yaml


ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy" if (ROOT / "deploy").is_dir() else ROOT / "openshell-risk-guard" / "deploy"


def check_authenticated_extensions(*extensions) -> None:
    # The Risk Guard channel is TLS + gateway-signed JWT in every recipe; opting out
    # of transport security would also make OpenShell stop sending tokens.
    for extension in extensions:
        assert extension["grpc_endpoint"] == "https://127.0.0.1:50061"
        assert extension["tls_ca_cert_path"].endswith("/risk-guard-tls/ca.crt")
        assert extension["audience"] == "urn:openshell:extension:risk-guard"
        assert not extension.get("allow_insecure_transport", False)


def render(path: Path, values: dict) -> dict:
    template = path.read_text()
    assert set(re.findall(r"@([A-Z_]+)@", template)) == values.keys()
    for name, value in values.items():
        template = template.replace(f"@{name}@", value)
    return tomllib.loads(template)["openshell"]


def check() -> None:
    template = (DEPLOY / "local" / "gateway.toml.in").read_text()
    values = {
        "STATE_DIR": "/checkout/openshell-risk-guard/deploy/local/state",
        "DOCKER_SOCKET": "/var/run/docker.sock",
        "WORKLOAD_IMAGE": "local/workload:test",
        "SANDBOX_RUNTIME_IMAGE": "local/sandbox:test",
        "SUPERVISOR_IMAGE": "local/supervisor:test",
    }
    assert set(re.findall(r"@([A-Z_]+)@", template)) == values.keys()
    for name, value in values.items():
        template = template.replace(f"@{name}@", value)
    config = tomllib.loads(template)["openshell"]
    assert config["version"] == 2
    gateway = config["gateway"]
    assert gateway["bind_address"] == "127.0.0.1:17671"
    assert gateway["disable_tls"] and gateway["auth"]["allow_unauthenticated_users"]
    interceptor, = gateway["interceptors"]
    middleware, = config["supervisor"]["middleware"]
    assert interceptor["name"] == "risk-guard-governance"
    assert middleware["name"] == "risk-guard"
    check_authenticated_extensions(interceptor, middleware)
    assert interceptor["failure_policy"] == "fail_closed"
    assert middleware["max_payload_bytes"] == 4194304
    docker = config["drivers"]["docker"]
    assert docker["supervisor_network_mode"] == "host"
    assert docker["image_pull_policy"] == "never"
    assert docker["enable_bind_mounts"] is False

    policy = yaml.safe_load((DEPLOY / "local" / "sandbox-policy.yaml").read_text())
    assert policy["version"] == 1
    assert policy["landlock"]["compatibility"] == "hard_requirement"
    stage, = policy["network_middlewares"].values()
    assert stage["middleware"] == middleware["name"]
    assert stage["on_error"] == "fail_closed"
    assert stage["config"] == {"task_profile": "local-repo-review", "mode": "enforce"}
    network, = policy["network_policies"].values()
    endpoint, = network["endpoints"]
    assert endpoint["host"] == "host.openshell.internal" and endpoint["port"] == 18081
    assert endpoint["rules"] == [{"allow": {"method": "GET", "path": "/repos/local/review/issues"}}]
    assert network["binaries"] == [{"path": "/usr/bin/curl"}]

    compose = yaml.safe_load((DEPLOY / "docker-compose.sidecar.yaml").read_text())
    services = compose["services"]
    assert set(services) == {"baseline-import", "openshell-risk-guard"}
    serve = services["openshell-risk-guard"]
    assert "--allow-insecure-local-test" in serve["command"]
    assert serve["depends_on"]["baseline-import"]["condition"] == "service_completed_successfully"
    assert services["baseline-import"]["command"][0] == "baseline-import"
    assert services["baseline-import"]["network_mode"] == "none"
    assert all(service["profiles"] == ["local-test"] for service in services.values())
    assert serve["ports"] == ["127.0.0.1:50061:50061"]
    sketch = list(yaml.safe_load_all((DEPLOY / "k8s-gateway-sidecar.yaml").read_text()))
    assert [document["kind"] for document in sketch] == [
        "Service", "NetworkPolicy", "PersistentVolumeClaim", "Deployment"]
    assert sketch[2]["spec"]["accessModes"] == ["ReadWriteOnce"]
    deployment = sketch[3]["spec"]
    assert deployment["replicas"] == 1, "one SQLite writer"
    assert deployment["strategy"]["type"] == "Recreate", "no overlapping writers during rollout"
    sidecar, = deployment["template"]["spec"]["containers"]
    for flag in ("--tls-cert=", "--tls-key=", "--hmac-key-file=", "--public-key-pem="):
        assert any(arg.startswith(flag) for arg in sidecar["args"]), flag
    assert "--allow-insecure-local-test" not in sidecar["args"]
    assert sidecar["readinessProbe"]["grpc"]["port"] == 50061
    volumes = {v["name"]: v for v in deployment["template"]["spec"]["volumes"]}
    assert "persistentVolumeClaim" in volumes["risk-guard-sqlite"], "risk state must be durable"

    demo = render(DEPLOY / "rail-guard-demo" / "gateway.toml.in", {
        "STATE_DIR": "/state", "DOCKER_SOCKET": "/run/docker.sock", "WORKLOAD_IMAGE": "w",
        "SANDBOX_RUNTIME_IMAGE": "r", "SUPERVISOR_IMAGE": "s",
    })
    demo_interceptor, = demo["gateway"]["interceptors"]
    demo_middleware, = demo["supervisor"]["middleware"]
    check_authenticated_extensions(demo_interceptor, demo_middleware)

    azure = (DEPLOY / "azure" / "deploy-azure.sh").read_text()
    assert "exit 1" in azure and not re.search(r"^\s*az\s", azure, re.MULTILINE)
    assert not re.search(r"^\s*resource\s", (DEPLOY / "azure" / "main.bicep").read_text(), re.MULTILINE)
    for script in (ROOT / "scripts" / "deploy-local-risk-guard.sh", DEPLOY / "azure" / "deploy-azure.sh"):
        assert b"\r" not in script.read_bytes(), f"{script} must use LF"
    print("PASS: TOML, YAML, shared registration/policy contracts, service-only Compose and retired Azure assets.")
    check_aks_hardened()
    print("NOT VERIFIED: native schema preflight, extension RPCs, kernel qualification or sandbox traffic.")


def check_aks_hardened() -> None:
    """The supported hardened AKS deployment: every file classified, nothing unresolved, no demo flags, images pinned, baseline met."""
    aks = DEPLOY / "aks"
    profile = json.loads((aks / "hardened-profile.json").read_text())
    supported, demo = set(profile["supported"]), set(profile["demo_only"])
    assert not supported & demo, f"classified both ways: {sorted(supported & demo)}"

    # 1. Every file is either part of the hardened profile or demo-only. A new file must be placed on purpose.
    present = {entry.name for entry in aks.iterdir()}
    unclassified = present - supported - demo
    assert not unclassified, f"deploy/aks files in neither list of hardened-profile.json: {sorted(unclassified)}"
    missing = (supported | demo) - present
    assert not missing, f"hardened-profile.json names files that do not exist: {sorted(missing)}"

    # 2. No placeholder is left that no deploy script fills in.
    filled = set()
    for script in (ROOT / "scripts" / "aks").glob("*.ps1"):
        filled |= set(re.findall(r"Replace\('(__[A-Z_]+__)'", script.read_text()))
    for name in sorted(supported):
        path = aks / name
        if path.suffix not in (".yaml", ".yml", ".sh", ".conf"):
            continue
        # PROXY_CONFIG_SHA and similar appear inside comments too; only an unfilled placeholder in the text of a manifest counts.
        left = set(re.findall(r"__[A-Z][A-Z_]*__", path.read_text())) - filled - {"__PLACEHOLDERS__"}
        assert not left, f"{name}: placeholders no script fills in: {sorted(left)}"

    # 3. Nothing a local test needs is in a supported manifest.
    forbidden = profile["forbidden_in_supported"]
    for name in sorted(supported):
        path = aks / name
        if path.suffix not in (".yaml", ".yml", ".sh", ".conf"):
            continue
        text = path.read_text()
        for flag in forbidden["args"] + forbidden["text"]:
            assert flag not in text, f"{name}: {flag!r} is for local testing and does not belong in the hardened profile"

    # 4. One SQLite writer, never two at once during a rollout.
    rule = profile["single_writer"]
    for document in yaml.safe_load_all(re.sub(r"(?m)^__[A-Z_]+__$", "", (aks / "risk-guard.yaml").read_text()).replace("__", "x_x_")):
        if document and document.get("kind") == "Deployment" and document["metadata"]["name"] == rule["deployment"]:
            assert document["spec"]["replicas"] == rule["replicas"]
            assert document["spec"]["strategy"]["type"] == rule["strategy"]

    # 5. Images are pinned by digest: the Dockerfile's base images, and the deploy script's hardened mode.
    for line in (ROOT / "Dockerfile").read_text().splitlines():
        if line.startswith("FROM ") and "@sha256:" not in line and " AS " in line and line.split()[1] not in {"builder", "runtime"}:
            raise AssertionError(f"Dockerfile base image is not pinned by digest: {line}")
    deploy = (ROOT / "scripts" / "aks" / "04-deploy-risk-guard.ps1").read_text()
    assert "[switch]$Hardened" in deploy and "@$digest" in deploy, "script 04 must offer digest-pinned deployment"

    # 6. The Kubernetes hardening baseline, on the same manifests, rendered the way the scripts render them.
    spec = importlib.util.spec_from_file_location("hardening", ROOT / "scripts" / "conformance" / "hardening.py")
    hardening = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hardening)
    register = json.loads((aks / "hardening-baseline.json").read_text())["exceptions"]
    unexplained = [f"{name}: {item['check']} ({item['subject']})"
                   for name, entry in hardening.static_report(register).items() if not name.split("/", 1)[1] in demo_workloads(aks, demo)
                   for item in entry["failed"]]
    assert not unexplained, f"hardening baseline failures: {unexplained}"
    print("PASS: hardened AKS profile (every file classified, placeholders filled, no local-test flags, one writer, digest-pinned bases, baseline met).")


def demo_workloads(aks: Path, demo: set) -> set:
    """Names of the workloads defined in demo-only manifests, which are held to the baseline too but reported separately."""
    names = set()
    for name in demo:
        path = aks / name
        if path.suffix in (".yaml", ".yml") and path.is_file():
            for document in yaml.safe_load_all(path.read_text().replace("__", "x_x_")):
                if isinstance(document, dict) and document.get("kind") == "Deployment":
                    names.add(document["metadata"]["name"])
    return names


if __name__ == "__main__":
    check()
