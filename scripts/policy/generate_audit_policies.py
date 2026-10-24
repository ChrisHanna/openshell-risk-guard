#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Regenerate deploy/aks/agents/<profile>/policy.audit.yaml for the fleet's profiles (support, release, cloud).

    python3 scripts/policy/generate_audit_policies.py            # rewrite the files
    python3 scripts/policy/generate_audit_policies.py --check    # fail if a committed file is out of date

The files are `policy-export --enforcement audit`: the profile's approved routes and deny list as OpenShell rules, in audit
mode, so a violation is logged and allowed. Set RG_BIN to a built openshell-risk-guard binary; without it `cargo run` is used.
Run it again whenever a profile's baseline.json or policy.yaml changes (tests/policy_export.rs fails until you do).
"""
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROFILES = ["support", "release", "cloud"]


def export(profile, out):
    base = f"deploy/aks/agents/{profile}"
    args = ["policy-export", "--baseline", f"{base}/baseline.json", "--policy", f"{base}/policy.yaml",
            "--enforcement", "audit", "--out", out]
    binary = os.environ.get("RG_BIN")
    cmd = [binary] + args if binary else ["cargo", "run", "--quiet", "--locked", "--"] + args
    subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def main():
    check = "--check" in sys.argv[1:]
    stale = []
    for profile in PROFILES:
        target = f"deploy/aks/agents/{profile}/policy.audit.yaml"
        if not check:
            export(profile, target)
            print(f"wrote {target}")
            continue
        tmp = f"{target}.check"
        try:
            export(profile, tmp)
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
        print("generated audit policies are current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
