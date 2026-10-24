#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Create the feature publisher's read-only OpenSearch account. Safe to run again.

    scripts/siem/install_publisher_user.py            # dry run: reads what exists, changes nothing
    scripts/siem/install_publisher_user.py --apply    # creates the role, the user, the role mapping and the Secret

What it makes (all names are constants below):
  * a role that may only READ the `ocsf-openshell*` indices (no cluster permissions, no writes, no other index),
  * an internal user mapped to that role only,
  * the Kubernetes Secret `opensearch-feature-publisher` in the siem namespace with the keys `username` and `password`, which the publisher pod mounts.

The password is generated here, goes straight into the Secret and into OpenSearch's user API through stdin, and is never printed, never written to a file and never
placed on a command line. Running again reuses the Secret's password, so it is idempotent. To rotate: `kubectl delete secret opensearch-feature-publisher -n siem`, then run with --apply.

Like install_content.py it talks to OpenSearch from inside the Dashboards pod (which already holds the admin password), so nothing is exposed.
"""
import argparse
import base64
import json
import os
import secrets
import string
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import install_content as ic  # noqa: E402  (its helpers: opensearch(), exec_in_pod())

NS = ic.NS
ROLE = "rg_feature_publisher"
USER = "rg-feature-publisher"
SECRET = "opensearch-feature-publisher"
OPENSEARCH = "https://opensearch-cluster-master:9200"

# Read search and mapping lookups on the OCSF OpenShell indices, and nothing else. `read` is the built-in action group indices:data/read/*.
ROLE_BODY = {
    "cluster_permissions": [],
    "index_permissions": [{"index_patterns": ["ocsf-openshell*"], "allowed_actions": ["read"]}],
    "tenant_permissions": [],
}


def kubectl(args, stdin=None):
    return subprocess.run(["kubectl", *args], input=stdin, capture_output=True)


def existing_password():
    """The password already in the Secret, or None. (Held in memory only.)"""
    result = kubectl(["get", "secret", SECRET, "-n", NS, "-o", "json"])
    if result.returncode != 0:
        return None
    data = json.loads(result.stdout).get("data", {})
    if "password" not in data:
        return None
    return base64.b64decode(data["password"]).decode()


def new_password():
    alphabet = string.ascii_letters + string.digits
    while True:
        text = "".join(secrets.choice(alphabet) for _ in range(28)) + secrets.choice("!_-")
        if any(c.islower() for c in text) and any(c.isupper() for c in text) and any(c.isdigit() for c in text):
            return text


def create_secret(password):
    """Create the Secret from a manifest on stdin (the password is never on a command line)."""
    manifest = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": SECRET, "namespace": NS,
                "labels": {"app.kubernetes.io/part-of": "risk-guard-demo"}}, "type": "Opaque",
                "data": {"username": base64.b64encode(USER.encode()).decode(), "password": base64.b64encode(password.encode()).decode()}}
    result = kubectl(["create", "-f", "-"], json.dumps(manifest).encode())
    if result.returncode != 0:
        raise SystemExit("The Secret was not created: " + result.stderr.decode("utf-8", "replace")[:300])


def put_user(password):
    """The user API takes the password in the body, which goes in on stdin."""
    answer = ic.opensearch("PUT", f"/_plugins/_security/api/internalusers/{USER}",
                           {"password": password, "backend_roles": [], "attributes": {}, "description": "Risk Guard feature publisher (read-only)"})
    if answer.get("status") not in ("OK", "CREATED"):
        raise SystemExit(f"The user was not created: {answer.get('message') or answer}")


def as_publisher(method, path, password, data=None):
    """Run one request as the publisher user and return only the HTTP status. The credentials go to curl as a config on stdin, not as arguments."""
    config = [f'url = "{OPENSEARCH}{path}"', f'user = "{USER}:{password}"', f'request = "{method}"', "silent", "insecure",
              'output = "/dev/null"', 'write-out = "%{http_code}"', 'header = "Content-Type: application/json"']
    if data is not None:
        config.append(f"data = {json.dumps(data)}")
    out = ic.exec_in_pod("curl -K -", ("\n".join(config) + "\n").encode())
    return out.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="make the changes (without it nothing is changed)")
    args = parser.parse_args()

    role = ic.opensearch("GET", f"/_plugins/_security/api/roles/{ROLE}")
    user = ic.opensearch("GET", f"/_plugins/_security/api/internalusers/{USER}")
    password = existing_password()
    print(f"role {ROLE}: {'exists' if ROLE in role else 'missing'}")
    print(f"user {USER}: {'exists' if USER in user else 'missing'}")
    print(f"secret {SECRET}: {'exists' if password else 'missing'}")
    if not args.apply:
        print("Dry run. Nothing was changed; pass --apply to create what is missing and bring the rest up to date.")
        return

    if password is None:
        password = new_password()
        create_secret(password)
        print(f"secret {SECRET}: created (keys: username, password)")
    answer = ic.opensearch("PUT", f"/_plugins/_security/api/roles/{ROLE}", ROLE_BODY)
    if answer.get("status") not in ("OK", "CREATED"):
        raise SystemExit(f"The role was not created: {answer.get('message') or answer}")
    put_user(password)
    answer = ic.opensearch("PUT", f"/_plugins/_security/api/rolesmapping/{ROLE}", {"users": [USER], "backend_roles": [], "hosts": []})
    if answer.get("status") not in ("OK", "CREATED"):
        raise SystemExit(f"The role mapping was not created: {answer.get('message') or answer}")

    # Prove the account does what it should and nothing more.
    checks = [("can search ocsf-openshell*", "POST", "/ocsf-openshell*/_search", '{"size":0}', "200"),
              ("cannot read another index", "GET", "/ocsf-synthetic/_count", None, "403"),
              ("cannot write to ocsf-openshell*", "PUT", "/ocsf-openshell-000002/_doc/rg-publisher-check", "{}", "403"),
              ("cannot use the security API", "GET", "/_plugins/_security/api/internalusers", None, "403")]
    failed = False
    for label, method, path, data, want in checks:
        got = as_publisher(method, path, password, data)
        ok = got == want
        failed |= not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label} (HTTP {got}, expected {want})")
    if failed:
        raise SystemExit("The account does not behave as a read-only account should; do not deploy the publisher until this is fixed.")
    print("Done. The publisher pod mounts the Secret; it reads the files on every interval, so a changed password needs no restart.")


if __name__ == "__main__":
    main()
