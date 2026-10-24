#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the OpenShell policies written from each task profile's baseline (deploy/aks/agents/<profile>/).

    python3 scripts/policy/generate_audit_policies.py            # rewrite the files
    python3 scripts/policy/generate_audit_policies.py --check    # fail if a committed file is out of date

Three kinds of file, all `policy-export` output:

  policy.audit.yaml         support, release, cloud     the fleet's policy today: the approved routes and deny list as OpenShell rules, in audit mode (a violation is logged and allowed)
  policy.enforce.yaml       support, release, cloud,    the same rules in enforce mode (a violation is refused by OpenShell). What the fleet runs when AGENT_POLICY_MODE=enforce.
                            demo-end-state
  policy.enforce.demo.yaml  every profile with a        DEMO ONLY: the enforce policy plus the reviewed extra allow rules in demo-exceptions.json (`--demo-exceptions`). Deliberately
                            demo-exceptions.json        weaker than the baseline; its rule name ends in "(DEMO EXCEPTIONS: n)". The fleet never uses it.

Set RG_BIN to a built openshell-risk-guard binary; without it `cargo run` is used. Run it again whenever a profile's baseline.json, policy.yaml or demo-exceptions.json
changes (tests/policy_export.rs fails until you do).
"""
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FLEET_PROFILES = ["support", "release", "cloud"]
ENFORCE_PROFILES = FLEET_PROFILES + ["demo-end-state"]
DEMO_PROFILES = ["release", "cloud", "demo-end-state"]
# (file name, profiles, enforcement, with the demo exceptions)
KINDS = [
    ("policy.audit.yaml", FLEET_PROFILES, "audit", False),
    ("policy.enforce.yaml", ENFORCE_PROFILES, "enforce", False),
    ("policy.enforce.demo.yaml", DEMO_PROFILES, "enforce", True),
]


def targets():
    for name, profiles, enforcement, demo in KINDS:
        for profile in profiles:
            yield profile, name, enforcement, demo


def export(profile, enforcement, demo, out):
    base = f"deploy/aks/agents/{profile}"
    args = ["policy-export", "--baseline", f"{base}/baseline.json", "--policy", f"{base}/policy.yaml", "--enforcement", enforcement, "--out", out]
    if demo:
        args += ["--demo-exceptions", f"{base}/demo-exceptions.json"]
    binary = os.environ.get("RG_BIN")
    cmd = [binary] + args if binary else ["cargo", "run", "--quiet", "--locked", "--"] + args
    subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def main():
    check = "--check" in sys.argv[1:]
    stale = []
    for profile, name, enforcement, demo in targets():
        target = f"deploy/aks/agents/{profile}/{name}"
        if not check:
            export(profile, enforcement, demo, target)
            print(f"wrote {target}")
            continue
        tmp = f"{target}.check"
        try:
            export(profile, enforcement, demo, tmp)
            with open(os.path.join(ROOT, tmp), "rb") as f:
                fresh = f.read()
            try:
                with open(os.path.join(ROOT, target), "rb") as f:
                    committed = f.read()
            except FileNotFoundError:
                committed = None
            if committed is None or committed.replace(b"\r\n", b"\n") != fresh:
                stale.append(target)
        finally:
            if os.path.exists(os.path.join(ROOT, tmp)):
                os.remove(os.path.join(ROOT, tmp))
    if stale:
        print("out of date (run scripts/policy/generate_audit_policies.py): " + ", ".join(stale), file=sys.stderr)
        return 1
    if check:
        print("generated policies (audit, enforce, demo) are current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
