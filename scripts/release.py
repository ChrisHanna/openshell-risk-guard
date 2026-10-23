#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Produce the release evidence for one built image: the checks, the image digest, SBOMs, vulnerability scans and a manifest.

    scripts/release.py --image <registry>/openshell-risk-guard:<tag> [--out release] [--allow-dirty]

The image must already be built and pushed (scripts/aks/02-build-image.ps1 or `docker build` and `docker push`). This script does not build it,
so what is released is exactly what was tested. It needs Docker (the scans run in the Trivy container) and Python with PyYAML.

What it does, in order, and stops at the first failure:

1. The working tree is clean (so the commit in the manifest describes what was built), unless `--allow-dirty`.
2. The deployment checker passes: hardened profile, placeholders, digest-pinned bases, Kubernetes baseline.
3. The image's digest is read from Docker, so deployments can pin `repository@sha256:...`.
4. SBOMs (CycloneDX) for the image's operating-system packages and for the Rust dependencies in Cargo.lock.
5. Vulnerability scans of both. **Gate:** a HIGH or CRITICAL finding that has a fixed version available fails the release. Findings with no fix
   are counted and listed by package in the manifest, not hidden and not blocking, since there is nothing to upgrade to.
6. `manifest.json` ties it together with a SHA-256 for every artifact. A short summary, without the registry's name, is written to
   `conformance/release-<commit>.json` to be committed.

Limits: the scanner's vulnerability database is whatever it downloads at run time (the manifest records when). A clean scan is a statement
about that moment. Rust code is scanned from Cargo.lock, not from the binary, which carries no dependency metadata.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
ROOT = Path(__file__).resolve().parent.parent
TRIVY = "aquasec/trivy:0.58.1"


def run(*command, check=True, capture=True):
    result = subprocess.run(command, capture_output=capture, text=True, cwd=ROOT)
    if check and result.returncode:
        sys.exit(f"{' '.join(command[:4])} failed:\n{(result.stderr or result.stdout)[-600:]}")
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trivy_image(out: Path, *arguments):
    mounts = ["-v", "//var/run/docker.sock:/var/run/docker.sock", "-v", f"{out}:/out"]
    run("docker", "run", "--rm", *mounts, TRIVY, *arguments)


def trivy_fs(out: Path, *arguments):
    run("docker", "run", "--rm", "-v", f"{ROOT}:/src:ro", "-v", f"{out}:/out", TRIVY, "fs", *arguments, "/src/Cargo.lock")


def summarise(path: Path):
    scan = json.loads(path.read_text())
    counts, unfixed, fixable = collections.Counter(), collections.Counter(), []
    for result in scan.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            severity = vulnerability["Severity"]
            counts[severity] += 1
            if severity in ("HIGH", "CRITICAL"):
                if vulnerability.get("FixedVersion"):
                    fixable.append(f"{vulnerability['VulnerabilityID']} in {vulnerability['PkgName']} (fixed in {vulnerability['FixedVersion']})")
                else:
                    unfixed[vulnerability["PkgName"]] += 1
    return {"by_severity": dict(counts), "high_or_critical_with_a_fix": fixable, "high_or_critical_without_a_fix_by_package": dict(unfixed)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", default="release")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    out = (ROOT / args.out).resolve()
    out.mkdir(exist_ok=True)

    dirty = run("git", "status", "--porcelain").stdout.strip()
    if dirty and not args.allow_dirty:
        sys.exit("The working tree has uncommitted changes, so the commit would not describe what was built:\n" + dirty[:400])
    commit = run("git", "rev-parse", "--short", "HEAD").stdout.strip()

    run(sys.executable, "scripts/check-risk-guard-deployment.py")
    print("deployment checker: pass", flush=True)

    inspected = run("docker", "inspect", "--format", "{{index .RepoDigests 0}}", args.image).stdout.strip()
    if "@sha256:" not in inspected:
        sys.exit("The image has no registry digest. Push it first.")
    repository, digest = inspected.split("@", 1)
    print(f"image digest: {digest}", flush=True)

    sbom_image, sbom_deps = out / f"sbom-image-{commit}.cdx.json", out / f"sbom-rust-deps-{commit}.cdx.json"
    scan_image, scan_deps = out / f"scan-image-{commit}.json", out / f"scan-rust-deps-{commit}.json"
    trivy_image(out, "image", "--format", "cyclonedx", "--output", f"/out/{sbom_image.name}", args.image)
    trivy_fs(out, "--scanners", "vuln", "--format", "cyclonedx", "--output", f"/out/{sbom_deps.name}")
    trivy_image(out, "image", "--scanners", "vuln", "--format", "json", "--output", f"/out/{scan_image.name}", args.image)
    trivy_fs(out, "--scanners", "vuln", "--format", "json", "--output", f"/out/{scan_deps.name}")

    scans = {"image": summarise(scan_image), "rust_dependencies": summarise(scan_deps)}
    fixable = scans["image"]["high_or_critical_with_a_fix"] + scans["rust_dependencies"]["high_or_critical_with_a_fix"]
    components = {
        "image": len(json.loads(sbom_image.read_text()).get("components", [])),
        "rust_dependencies": len(json.loads(sbom_deps.read_text()).get("components", [])),
    }

    dockerfile = (ROOT / "Dockerfile").read_text()
    manifest = {
        "release": commit,
        "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "image_repository": repository,
        "image_digest": digest,
        "deploy_with": f"scripts/aks/04-deploy-risk-guard.ps1 -ImageTag <tag> -Hardened   (pins {repository.split('/')[-1]}@{digest[:19]}...)",
        "base_images": re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE),
        "toolchain": (ROOT / "rust-toolchain.toml").read_text().strip().splitlines()[-1] if (ROOT / "rust-toolchain.toml").exists() else None,
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        "scanner": TRIVY,
        "scans": scans,
        "sbom_components": components,
        "gate": {"rule": "no HIGH or CRITICAL finding with a fixed version available", "passed": not fixable, "failures": fixable},
        "artifacts": {p.name: sha256(p) for p in (sbom_image, sbom_deps, scan_image, scan_deps)},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    summary = {k: v for k, v in manifest.items() if k not in ("image_repository", "deploy_with")}
    summary["image_repository"] = "/".join(repository.split("/")[1:])  # no registry host in committed evidence
    (ROOT / "conformance" / f"release-{commit}.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"gate_passed": not fixable, "scans": scans, "sbom_components": components}, indent=2))
    sys.exit(0 if not fixable else 1)


if __name__ == "__main__":
    main()
