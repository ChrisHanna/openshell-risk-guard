# Hardened install and release

One supported path to a hardened deployment on AKS, and the evidence it leaves behind. The checks extend the existing deployment checker
(`scripts/check-risk-guard-deployment.py`); there is no second checklist.

## What "hardened" means here

[`deploy/aks/hardened-profile.json`](../deploy/aks/hardened-profile.json) puts every file under `deploy/aks` in one of two lists: **supported**
(part of the hardened deployment) or **demo-only** (the fixture, the demo workloads, the agent fleet, the token-grant demo). A new file in neither
list fails the check, so nothing is silently in or out.

The checker (CI runs it, and `scripts/test_check_aks_profile.py` shows it fails when it should) enforces, for the supported files:

| Rule | Why |
|---|---|
| Every `__PLACEHOLDER__` is one a deploy script fills in | an unrendered manifest never reaches the cluster |
| No `--allow-insecure-local-test`, `--allow-local-dev-principal`, `:latest`, `imagePullPolicy: Never` or insecure transport | local-test settings stay out of the profile |
| One `risk-guard` replica with the `Recreate` strategy | one SQLite writer, never two during a rollout |
| Dockerfile base images pinned by digest | a rebuild uses the same bytes |
| Script 04 can deploy by digest (`-Hardened`) | what runs is exactly what was released |
| The [Kubernetes baseline](hardening.md) is met on the rendered manifests | non-root, dropped capabilities, seccomp, limits, no API token unless needed |

## The path

```bash
# 1. Build and push (commit first: the release record names the commit)
powershell scripts/aks/02-build-image.ps1            # add -LocalDocker if the registry's build service is unreachable
# 2. Release evidence for that image: checks, digest, SBOMs, scans, manifest
python scripts/release.py --image <registry>/openshell-risk-guard:<tag>
# 3. Deploy by digest, on the security node pool
powershell scripts/aks/04-deploy-risk-guard.ps1 -ImageTag <tag> -Hardened
# 4. Conformance evidence from the running deployment
python scripts/conformance/hardening.py --out conformance/hardening.json
python scripts/conformance/placement.py --out conformance/placement-after-hardening.json
python scripts/conformance/failure_containment.py --out conformance/failure-containment.json
```

`scripts/release.py` gates the release on one rule: **no HIGH or CRITICAL finding that has a fixed version available**. Findings with no fix are
counted and listed by package in the manifest; they do not block, because there is nothing to upgrade to. The output is
`release/manifest.json` (image digest, base images, toolchain, `Cargo.lock` hash, scan summaries, a SHA-256 for each artifact), two CycloneDX SBOMs
and two scan reports (all in the untracked `release/` folder), and a short summary, `conformance/release-<commit>.json`, which is committed.

## What this release shows (`8b9aa17`)

* **Runtime image changed to distroless.** The Debian slim runtime carried 43 HIGH findings, none with a fix, all in `util-linux` and `login`
  packages the service does not use. A distroless runtime (glibc, libstdc++ and CA certificates, no shell or package manager) has none:
  23 MEDIUM and 8 LOW remain, and 0 HIGH or CRITICAL. The service's probes run its own binary, so nothing needed a shell.
* **Rust dependencies:** 383 components in the SBOM, 0 known vulnerabilities (and `cargo deny` runs in CI as well).
* The image's operating-system SBOM lists 15 components.

## Upgrade, rollback, roll forward (run on the live cluster)

[`conformance/upgrade-drill.json`](../conformance/upgrade-drill.json), from `scripts/conformance/upgrade_drill.py`: upgrade from the previous image
to this one by digest, roll back with `kubectl rollout undo`, roll forward again. At each step it snapshots every agent's restrictions and the
quarantine list, and runs an allowed read and a refused destructive call through the deployed proxy.

* No restriction was lost at any step; 22 restrictions were present throughout.
* The rolled-back image opened a database the newer image had written to, and worked.
* Each restart took about 80–110 s from start of deploy to a working path. During that time requests fail closed.
* No database migration changed between these two images, so this shows compatibility for that case only.

## Not done, and why

* **A clean first-time install** into an empty cluster, and **teardown**, were not run. Both would destroy or duplicate the cluster the demo
  runs on and cost an hour or more of cloud time. The scripts (`01` to `21`, `99-teardown`) are the path, and the checker covers what can be
  checked offline, but there is no evidence a second developer has done it end to end. That is the main gap against the acceptance test.
* **Image signing and provenance attestations** are not produced.
* **The other workloads** (proxies, SPIRE) are not yet deployed by digest; only Risk Guard is, via `-Hardened`. Scripts 17 and 18 re-apply
  manifests that pin the proxies to the ordinary node pool, so run `21-harden-placement.ps1 -Apply` after them.
* The scanner's database is whatever it downloaded at run time; a clean result is true of that moment.
