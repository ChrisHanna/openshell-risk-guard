<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
SPDX-License-Identifier: Apache-2.0
-->

# Architecture and security review: OpenShell, Risk Guard and OpenSearch

A technical review of the three-system loop: what each system is responsible for, what the SIEM contributes to Risk Guard, how that compares with industry SIEM/UEBA architectures, and where the current boundaries sit. Every claim carries its evidence level:

* **live** = run against the cluster in this project (a demo act, a probe, the smoke test)
* **tested** = covered by an automated test, not run live
* **read** = true of the code or documents, not exercised
* **design** = intended, not built

## 1. The position in one paragraph

OpenShell is the hard fence: fixed rules, filesystem confinement, a policy prover. Risk Guard is the judge OpenShell calls for what a fixed rule cannot say: which resource, whether this is normal for this workload, what happened last time. OpenSearch is the memory: every event from both, and the only place that sees across sandboxes and over time. The integration is real and it fails closed. **But today OpenSearch changes no decision in the fleet**; its influence on enforcement is one capped, add-only rule that enforces in a single demo profile. Its strongest, verified contribution is different: it is the evidence that made it safe to switch OpenShell from audit to enforce.

## 2. What each system is responsible for

| | Owns | Decides | Cannot do |
|---|---|---|---|
| **OpenShell** | Network and filesystem policy, credential injection, sandbox isolation, the prover | Allow or deny by binary, host, method, path (**live**) | Judge a resource, remember a workload across sandboxes, learn |
| **Risk Guard** | Task rules, locks, quarantine, behavioral score, adaptive learner, change control | Allow or deny the calls OpenShell lets through, in milliseconds: p50 2.6 ms, p95 3.2 ms in the release gate (**tested**, scripted traffic) | See calls OpenShell refused (it learns of them only through OpenSearch); see paths of encrypted tunnels (**read**) |
| **OpenSearch** | Events from both systems, dashboards, monitors, features | Nothing. It cannot block a call | Anything in the hot path, by design |

## 3. How the SIEM improves Risk Guard's responsibilities: scorecard

| Risk Guard responsibility | What OpenSearch contributes | Status | Honest limit |
|---|---|---|---|
| **Earn trust to enforce** (audit, then enforce) | The agreement tool compares what OpenShell would refuse with what Risk Guard refused over 24 h | **live**: about 107 to 118 of about 109 to 120 would-blocks matched, 0 that only OpenShell would add; the fleet then moved to enforce | The promotion gate still says HOLD; the window is one day |
| **Evidence and audit** | Every decision and denial is exported as OCSF and searchable | **live**: smoke test finds every call of the demo in the SIEM | Not append-only; a short window is unexported (gap 5) |
| **Per-call score** | `siem_context` rules R1 to R6 (`openshell_denials_5m`, `refusal_ratio_15m_permille`, `new_routes_1h`, `fleet_workloads_with_denials_5m`, `anomaly_grade_15m_permille`, and `R6 probing × novel access`), capped at 15 points (max 30), add-only, served from an in-memory cache (`SiemFeatureCache`) | **live** mechanism (demo act F: denials counted, handed over, score rose); enforcing in the end-state profile | Fleet profiles watch by default until promoted; **value is unmeasured on real external traffic** |
| **Learning** | The same counts reach the adaptive learner as bounded context | **tested** (mapping and learner rules); wired 2026-10-24 | No live model has used them yet; the one evaluation is synthetic with context correlated to attacks by construction: it proves the mechanism, not a benefit |
| **Containment** | Alert monitors can ask Risk Guard to quarantine, tighten-only | built, **dry-run**: recorded, nothing happens | Not enforcing; only one monitor sends signals |
| **Suggest what to allow** | `suggest_baselines.py` proposes hosts and rate limits from the SIEM; route suggestions come from Risk Guard's own history; the Policy Studio (`POST /api/studio/verify`) synthesizes and Z3-verifies tightened OpenShell policies | **live**/**tested** | A person proposes and a second person approves |
| **Anomaly scores** | OpenSearch RCF anomaly detectors (`anomaly_grade_15m_permille`) feed Rule R5 (+3 at >=400, +6 at >=700) and Rule R6 (+6 when combined with novel access) | **live**/**tested** | Synthetic data on cluster; RCF detector results trail real time by about 60–85 s |
| **Notice a bypassed supervisor** | Tunnel gate flags a sandbox that goes quiet; a monitor watches | **tested**, shadow | Defeated by an attacker who keeps sending harmless requests (gap 7) |

**How fast the SIEM path is** (measured, **live**, two samples): an OpenShell denial is searchable in OpenSearch after 5 to 8 s, and Risk Guard scores a call with the resulting feature after 20 to 34 s, mostly the publisher's 30 s cycle. That suits probing spread over minutes and not a fast burst; fast bursts are Risk Guard's own job (rate windows, locks).

## 4. Compared with how others use SIEM data

| Approach | Where the decision is made | How SIEM data is used | Latency | What we do differently |
|---|---|---|---|---|
| Splunk risk-based alerting | Analyst, after a score crosses a line | Detections add risk to an entity, rolled up over 7 days by a scheduled search | Minutes (every 20 min by default) | Ours is inline and per call; add-only and capped; but we have no cumulative per-entity roll-up |
| Microsoft Sentinel UEBA | Analyst | Per-entity baselines, two scores (near-real-time and batch) | Near real time to batch | We also split fast (Risk Guard) and slow (OpenSearch) |
| Elastic entity risk plus ML jobs | Analyst, or rules paired with ML jobs | Risk 0 to 100 from alert severity, frequency, asset criticality | Scheduled | We lack asset criticality and watchlists |
| NVIDIA Morpheus digital fingerprinting | Downstream consumer | Per-entity autoencoder, z-score at 2.0 | Streaming pipeline | Natural future source for our anomaly feature; not integrated |
| Entra continuous access evaluation / CAEP | The enforcement point, on a pushed event | Standard push of "risk changed" | Up to 15 min propagation (Microsoft) | Our signals path is the same idea, bespoke and in dry run; CAEP defines no risk-level event |
| AI-agent vendors (CrowdStrike, Exabeam) | Vendor platform | Correlate agent telemetry with endpoint and SIEM | Vendor claims only | Unverified by us; no independent benchmark found |

**Where we are genuinely different:** the SIEM-derived score acts in an inline allow-or-deny path for agent calls, and it is bounded (cap, add-only, closed vocabulary, expiry), recorded per decision and replayable (1,694 of 1,694 requests identical across 415 episodes in the release gate, **tested**). **Where we are behind:** no standard protocol, no cumulative entity risk, no asset weighting, no real-data evaluation.

## 5. Security architecture assessment

### Strengths (each with its evidence)

* **Fails closed everywhere** (**live**/**tested**): sidecar unreachable, slow or erroring means blocked; restarts cost an 80 to 110 s outage rather than a bypass.
* **Extension can only narrow** (**read**): the contract is `FinalAllow = OpenShellAllow AND RiskPermit`; Risk Guard cannot widen OpenShell. It reads no body, headers or query (a test sends a secret and proves it is ignored).
* **Monotonic state** (**tested**): locks persist across sidecar restarts and across sandboxes for the same workload, and are never cleared automatically.
* **Loosening needs two people** (**live**/**tested**: two Entra administrator accounts—primary admin + `learningnemo-approver@christopherghannagmail.onmicrosoft.com`—are configured on the console's 2-Person Approvals Desk).
* **Policy changes are prover-checked** (**live**/**tested**): candidates must be proved no wider than the current policy by OpenShell's Z3 solver (~1–11 ms in the Policy Studio), and a proof that times out is refused, not passed.
* **Replayable decisions** (**tested**): each decision stores the exact SIEM features it used.
* **Measured before enforced** (**live**): the OpenShell fleet moved from audit to enforce on agreement evidence.

### Threats to the SIEM integration

| Threat | Mitigation (evidence) | Residual |
|---|---|---|
| A forged batch posted to `/features` | Mutual TLS plus a SPIFFE allow-list; the source comes from the certificate; unknown fields are refused; closed vocabulary; size and rate limits; every batch audited (**tested**) | The publisher and the signal forwarder share one SVID in one pod (**read**): a compromised container there can post both features and signals |
| OpenSearch compromised or poisoned (fake denial events) | Features can only add, cap 15, expire after 10 min; they cannot loosen, touch locks or release a quarantine (**tested**) | Once a profile enforces the rule, fake events could push a borderline workload over a threshold (an availability attack). Fleet profiles only watch today |
| Suppressed events | Removing events only removes the extra points; the base rules and locks are unaffected (**read**) | None to protection; evidence could be lost (gap 5) |
| SIEM down or slow | Features are read from a local table; nothing in the decision path waits on OpenSearch (**read**, unit-tested for the no-features case) | Not drill-tested on the cluster |
| A sandboxed agent manipulates its own score | It can cause its own OpenShell denials, which only raises its own score; the fleet campaign rule needs three workloads (**read**) | None found; not red-teamed |
| Feedback loop | R2 uses Risk Guard's own refusal ratio, so refusals can raise later scores (**read**) | Bounded by the cap; could entrench a borderline workload |
| Evidence deleted by a database administrator | Events exported to OpenSearch, 14-day retention | The SIEM is not append-only (gap 5) |

### Where the architecture is thin

1. **OpenSearch's influence on decisions is small and unproven.** The honest line is "bounded context that has run live and shows the mechanism; its value has not been measured on real traffic."
2. **The slow path.** 20 to 34 s end to end is too slow to stop a burst. The fix is design, not tuning: tap OpenShell's denial events straight into Risk Guard and keep OpenSearch for history.
3. **No standard protocol.** The signals and features paths are bespoke; CAEP/SSF would make them interoperable but defines no risk event, so it needs a custom one.
4. **Learned controls are immature.** Every fleet baseline has 0 training sessions; the learner has not yet produced a model for the demo profile; detection evidence is scripted traffic on our own agents.
5. **Single node.** No high availability; about 100 decisions per second ceiling.
6. **A compromised supervisor** can stop calling Risk Guard (gap 7); the tunnel gate and network fence limit it only partly.
7. **No hardware-backed trust.** Nothing here integrates BlueField, DOCA or confidential computing (design note only).

## 6. What would make the story stronger, in order

| # | Change | Why it matters | Effort |
|---|---|---|---|
| 1 | Cut the publisher cycle to 5 s and tune collector batching | Takes 20 to 34 s to roughly 10 to 15 s | Config plus a deploy |
| 2 | A "time to protect" test: how many calls of a fast burst get through before Risk Guard reacts, per design | Turns "too slow" into a number and chooses between designs | A day |
| 3 | Stream tap: OpenShell denial events straight to Risk Guard, hot counters in memory | The real-time answer; OpenSearch keeps history | Design plus build |
| 4 | Give the publisher its own service account and SVID | Removes the shared-identity weakness | Small |
| 5 | Evaluate the SIEM features on recorded real fleet traffic with and without them | Replaces "mechanism works" with "this is what it changes" | A few days |
| 6 | Cumulative per-workload risk with decay, and resource criticality | Closes the two biggest gaps against Splunk and Elastic | Design plus build |
| 7 | Use Morpheus-style per-entity scoring as the anomaly feature | NVIDIA-relevant; replaces unused OpenSearch detector scores | Design only until real data exists |
| 8 | SSF/CAEP envelope with a custom risk event for the signals path | Interoperability story | Moderate; no Rust library found |

## 7. Architectural summary and FAQ

**Executive summary.** OpenShell permits, Risk Guard judges, OpenSearch remembers. OpenShell's extension points allow inline behavioral judgment without forking the runtime, and the extension can only narrow what OpenShell allows (`FinalAllow = OpenShellAllow ∧ RiskPermit`). OpenSearch provides cross-sandbox evidence—verifying that enforcing generated static policies on the fleet adds zero false blocks—and feeds Risk Guard bounded, add-only features (`R1`–`R6`). Because the SIEM pipeline operates on a 5–30 second window, it supplies context for multi-minute probing campaigns, while sub-millisecond locks and rate windows in Risk Guard stop fast inline bursts.

**Explicit non-goals and current boundaries:**

* OpenSearch never scores or blocks requests directly in the hot path
* SIEM feature impact is verified on scripted and red-team episodes rather than external production attackers
* SIEM signals (`POST /v1/signals`) run in dry-run mode on the demo cluster by default
* Garak (`garak_scan`) is packaged in the agent container and paced for model API quotas, while call-level fuzzing (`387/387` blocked) runs in CI
* Hardware-backed out-of-band enforcement (NVIDIA Sentry / BlueField) is a separate layer not replaced by this software sidecar

**Common architectural questions:**

| Question | Answer |
|---|---|
| Why not just use the SIEM to block? | Latency and availability: the SIEM runs on a clock of seconds to minutes and must never be a dependency of the decision. It informs; Risk Guard decides. |
| What if OpenSearch is compromised? | It can raise a score by at most 15 points (hard cap 30), only where the rule enforces, and cannot loosen anything or touch a lock. Worst case is a false denial, which is why fleet profiles start in watching mode until evidence supports enforcing. |
| What is the evidence it works? | Live demo acts; a 24 h agreement run between OpenShell and Risk Guard; a release gate on scripted traffic with measured latency; a replay that reproduces every decision. |
| What are the next engineering priorities? | Sub-10s feature publishing, a direct stream tap for OpenShell floor denials, and evaluation across longer-horizon fleet captures. |
| How is this different from Splunk or Sentinel? | Traditional UEBA scores entities asynchronously for human analysts; Risk Guard consumes bounded SIEM-derived context inside a sub-millisecond inline allow/deny gate, with a cap, an expiry, a per-decision record, and deterministic replay. |
