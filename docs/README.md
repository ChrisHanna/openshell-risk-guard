<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Documentation Index

 Organized reference documentation for **OpenShell Behavioral Risk Guard (`openshell-risk-guard`)**.

## 1. Architecture & System Overview
- [The Story: OpenShell, Risk Guard, and OpenSearch](./the-story.md) — High-level overview of the three-system loop and repository map.
- [How It Works End-to-End](./how-it-works.md) — Technical walkthrough of the inline scorer, tunnel gate, SQLite state, SPIFFE identity, SIEM loop, and governance.
- [Who Blocks, Who Recommends, Who Decides](./who-does-what.md) — Clear division of responsibilities between System 1 (OpenShell), System 2 (Risk Guard), OpenSearch, and human operators.
- [Architecture & Security Review](./architecture-review.md) — Critical evaluation of the architecture, split-speed SIEM design, industry comparison, and threat mitigations.
- [Architecture Specification](./architecture.md) — Component topology, gRPC extension contracts, and network boundaries.
- [Where Risk Guard Fits (Positioning)](./positioning.md) — How Risk Guard complements OpenShell and out-of-band hardware enforcement (NVIDIA Sentry).
- [ADR 0001: Security Placement](./adr/0001-security-placement.md) — Architectural decision record on node pool isolation and sidecar placement.
- [Confidential Computing Design](./confidential-computing-design.md) — Design note for hardware-backed attestation and confidential containers.

## 2. Behavioral Scoring, Identity & Policy Graduation
- [System Design](./design.md) & [Requirements](./requirements.md) — Formal invariants, two-tier ratchet mechanics, and data model.
- [Anomaly Detection & Scoring Model](./anomaly-detection.md) — Signal weights, baseline comparison, and risk score computation.
- [Adaptive Learning (v2)](./adaptive-v2.md) — Shadow behavioral learning, promotion rules, and maturity credits.
- [ML Training Experiments](./ml-training.md) — Offline model comparison on synthetic episode traces.
- [Hardening & Z3 Policy Graduation](./hardening.md) — Synthesizing least-privilege OpenShell YAML candidates and verifying non-expansion with `openshell-prover` (Z3).
- [Fleet Policy Modes](./fleet-policy-modes.md) — Operating sandboxes in hand-written, `audit`, and `enforce` OpenShell policy modes.
- [Workload Identity & SPIFFE](./workload-identity.md) — Durable workload IDs, SPIRE X.509/JWT-SVID enrollment, and the Envoy `ext_authz` tunnel gate.
- [Identity Hardening](./identity-hardening.md) & [Security Model](./security-model.md) — Principal binding, token verification, and key rotation.

## 3. SIEM & OpenStream Telemetry Loop
- [SIEM Integration](./siem-integration.md) — OCSF 1.8 event export over OTLP/HTTP and reference OpenSearch pipeline.
- [SIEM Guide (Dashboards & Monitors)](./siem-guide.md) — OpenSearch dashboards, anomaly detectors, and watch-only monitors.
- [SIEM Features Design](./design-siem-features.md) & [SIEM Features Publisher](./siem-features-publisher.md) — Closed-vocabulary SIEM risk features (`POST /features`, rules `R1`–`R6`).
- [SIEM Signals](./siem-signals.md) — Authenticated tighten-only quarantine signals (`POST /v1/signals`) over SPIFFE mTLS.

## 4. Operations, Deployment & Governance
- [Getting Started](./getting-started.md) — Quickstart options from a 10-minute local sample database to full cluster deployment.
- [Running on AKS](./aks.md) — Numbered Azure Kubernetes Service deployment guide (`scripts/aks/01`–`26`), Kata micro-VMs, and Entra ID sign-in.
- [Local Demo & Deployment](./demo.md) — Running the local gateway and fixture stack.
- [Operating Risk Guard](./operations.md) — TLS/JWT setup, guardrail tuning, metrics, and audited lock recovery.
- [Two-Person Approval](./two-person.md) — Proposer ≠ approver governance for loosening actions, baseline updates, and OpenShell policy graduation.
- [Promotion Gate](./promotion-gate.md) — Evidence gate for promoting rules from watching (`shadow`) to `enforce`.
- [Backup & Recovery](./recovery.md) — Online `VACUUM INTO` backups, SHA-256 verification, and restore drills.
- [Deployment Security](./deployment-security.md), [Release Gate](./release.md), & [Sizing and Cost](./sizing-and-cost.md) — Kubernetes hardening, SBOM/provenance checks, and resource footprint.

## 5. Verification, Red-Team & Live Walkthroughs
- [Demo Runbook](./demo-runbook.md), [Partner Demo](./partner-demo.md), & [End-State Demo](./end-state-demo.md) — Structured walkthroughs of the live cluster and Studio console.
- [Red-Team Catalog & Fuzzer](./red-team.md) — 24-scenario attack catalog and 387-mutation path/encoding fuzzer.
- [Adaptive Red-Team Agent & Garak](./red-team-agent.md) — In-sandbox LLM attacker and Garak vulnerability scanner integration.
- [Policy Path Edge Cases](./policy-path-edge-cases.md) — Empirical conformance results across 166 raw HTTP path evasions.
- [Detection Results](./detection-results.md), [Benchmark](./benchmark.md), [Decision Replay](./replay.md), & [Results Sheet](./results-sheet.md) — Measured accuracy, latency histograms, deterministic replay, and conformance summary.
- [Production-Readiness Gaps](./production-gaps.md) — Prioritized engineering roadmap between the reference prototype and production scale.
