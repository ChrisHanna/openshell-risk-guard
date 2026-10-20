"""Offline syntax/contract checks; this does not certify a running OpenShell sandbox.

Run with Python 3.11+ and PyYAML. No files are written and no daemons are contacted.
"""

from pathlib import Path
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
    assert middleware["max_payload_bytes"] == 16384
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
    print("NOT VERIFIED: native schema preflight, extension RPCs, kernel qualification or sandbox traffic.")


if __name__ == "__main__":
    check()
