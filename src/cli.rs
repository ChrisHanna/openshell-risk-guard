// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Operator CLI definitions and unified execution entrypoint (Wave 3 - `t09-server-cli-bin`).

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use crate::auth::JwtAuthVerifier;
use crate::detector::{InteractionRiskDetector, compute_baseline_hash, load_baseline_profile};
use crate::error::{Result, RiskGuardError};
use crate::fixture::{PROFILE_REPO_TRIAGE_READONLY, build_standard_corpus};
use crate::hardening::ProverHardeningEngine;
use crate::interceptor_service::RiskGuardInterceptorService;
use crate::middleware_service::RiskGuardMiddlewareService;
use crate::normalizer::CanonicalNormalizer;
use crate::store::SqliteRiskStore;
use crate::types::{
    AuthVerifier, DecisionOutcome, EnforcementMode, EpochRecord, HardeningEngine, RawRequestInput,
    RiskStore,
};

/// Unified `openshell-risk-guard` gRPC server and operator CLI.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "openshell-risk-guard",
    version,
    about = "Behavioral risk-based conditional access and monotonic policy guard for OpenShell"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Supported subcommands for `openshell-risk-guard`.
// One value is built per process start, so the size of the largest variant (`Serve`, with its many options) costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Commands {
    /// Start the unified SupervisorMiddleware + GatewayInterceptor gRPC server.
    Serve {
        #[arg(long, default_value = "127.0.0.1:50061")]
        listen: SocketAddr,
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value = "local-gateway")]
        gateway_id: String,
        #[arg(long, default_value = "urn:openshell:extension:risk-guard")]
        audience: String,
        /// Gateway's Ed25519 extension-JWT public key (mounted file).
        #[arg(long, env = "RISK_GUARD_PUBLIC_KEY_PEM")]
        public_key_pem: Option<PathBuf>,
        #[arg(long)]
        allow_insecure_local_test: bool,
        #[arg(
            long,
            env = "RISK_GUARD_DEFAULT_TASK_PROFILE",
            default_value = "repo-triage-readonly"
        )]
        default_task_profile: String,
        /// Compatibility only: permit sandbox-only decisions without trusted workload attribution.
        #[arg(long)]
        allow_unattributed: bool,
        /// PEM certificate chain for the gRPC listener (required off loopback).
        #[arg(long, env = "RISK_GUARD_TLS_CERT")]
        tls_cert: Option<PathBuf>,
        /// PEM private key for the gRPC listener (required off loopback).
        #[arg(long, env = "RISK_GUARD_TLS_KEY")]
        tls_key: Option<PathBuf>,
        /// Mounted secret holding the resource HMAC key (at least 32 bytes).
        #[arg(long, env = "RISK_GUARD_HMAC_KEY_FILE")]
        hmac_key_file: Option<PathBuf>,
        /// Mounted API semantic map (route templates, impact, optional host); defaults to the built-in demo map.
        #[arg(long, env = "RISK_GUARD_API_SEMANTICS")]
        api_semantics: Option<PathBuf>,
        /// Principals allowed to attach a sandbox to a workload ID when creating it, as
        /// `operator:<subject>` or `user:<subject>` (repeat or comma-separate). Without any,
        /// `openshell.nvidia.com/agent-id` is ignored and sandboxes are bound with `run-bind`.
        #[arg(
            long = "agent-binding-principal",
            env = "RISK_GUARD_AGENT_BINDING_PRINCIPALS",
            value_delimiter = ','
        )]
        agent_binding_principals: Vec<String>,
        /// Register a workload ID that an allowlisted creator names but nobody registered.
        #[arg(long)]
        auto_register_agents: bool,
        /// Bind sandboxes that carry no workload label to a workload derived from the
        /// authenticated (workspace, principal) that created them. Operators and users
        /// only; the ID cannot be chosen or forged from the request.
        #[arg(
            long = "workload-from-principal",
            env = "RISK_GUARD_WORKLOAD_FROM_PRINCIPAL"
        )]
        workload_from_principal: bool,
        /// Let OpenShell's unauthenticated local-development user own a workload and pass the
        /// label allowlist. For local testing only: that caller proves nothing about who it is.
        #[arg(
            long = "allow-local-dev-principal",
            env = "RISK_GUARD_ALLOW_LOCAL_DEV_PRINCIPAL"
        )]
        allow_local_dev_principal: bool,
        /// Keep detailed decisions this many days; older ones are pruned hourly unless an active lock or an adaptive
        /// training window still needs them. 0 keeps everything (the per-epoch cap still applies). Epochs, locks and
        /// the audit of cleared locks are never pruned.
        #[arg(
            long = "decision-retention-days",
            env = "RISK_GUARD_DECISION_RETENTION_DAYS",
            default_value_t = 30
        )]
        decision_retention_days: u32,
        /// Also serve the middleware on this address with mutual TLS, identifying each caller by the SPIFFE ID in its X.509-SVID.
        /// Needs --svid-bundle and --svid-trust-domain, and reuses --tls-cert/--tls-key as the server identity.
        #[arg(long = "svid-listen", env = "RISK_GUARD_SVID_LISTEN")]
        svid_listen: Option<SocketAddr>,
        /// PEM file with the SPIFFE trust bundle (the certificate authorities that sign SVIDs); re-read when it changes.
        #[arg(long = "svid-bundle", env = "RISK_GUARD_SVID_BUNDLE")]
        svid_bundle: Option<PathBuf>,
        /// A trust domain whose SPIFFE IDs may call the SVID listener (repeatable).
        #[arg(
            long = "svid-trust-domain",
            env = "RISK_GUARD_SVID_TRUST_DOMAINS",
            value_delimiter = ','
        )]
        svid_trust_domains: Vec<String>,
        /// A proxy (by SPIFFE ID) trusted to say who its downstream caller is. When any are given, the SVID listener also serves
        /// Envoy's external authorization service, so the proxy can ask Risk Guard to allow or deny each request (repeatable).
        #[arg(
            long = "svid-proxy-id",
            env = "RISK_GUARD_SVID_PROXY_IDS",
            value_delimiter = ','
        )]
        svid_proxy_ids: Vec<String>,
        /// Also answer the tunnel checks of OpenShell's upstream proxy: connections from the supervisor pods in this namespace are
        /// matched to their sandbox by pod address, and refused when Risk Guard has locked the sandbox's workload (or knows
        /// nothing about it). Needs --svid-proxy-id, and read access to pods in that namespace.
        #[arg(long = "tunnel-pod-namespace", env = "RISK_GUARD_TUNNEL_POD_NAMESPACE")]
        tunnel_pod_namespace: Option<String>,
        /// What a latched (strict-epoch) restriction does to a sandbox's tunnels: `shadow` records it, `enforce` refuses them.
        /// A quarantine set by an operator is always enforced. Restrictions are scoped to one kind of request, so shadow first.
        #[arg(
            long = "tunnel-restriction-mode",
            env = "RISK_GUARD_TUNNEL_RESTRICTION_MODE",
            default_value = "shadow"
        )]
        tunnel_restriction_mode: String,
        /// How long, in seconds, a sandbox that has been reporting requests may go quiet before its next tunnel is flagged as coming from a
        /// silent supervisor (recorded, not blocked, unless the profile sets the `supervisor_silent` rule to enforce). 0 turns it off.
        #[arg(
            long = "tunnel-silence-seconds",
            env = "RISK_GUARD_TUNNEL_SILENCE_SECONDS",
            default_value_t = 600
        )]
        tunnel_silence_seconds: u64,
        /// Address for the signals listener, through which a SIEM can ask Risk Guard to quarantine a workload for a while (tighten only).
        /// Off unless given. Needs `--signals-token-file` or the RISK_GUARD_SIGNALS_TOKEN environment variable.
        #[arg(long = "signals-listen", env = "RISK_GUARD_SIGNALS_LISTEN")]
        signals_listen: Option<SocketAddr>,
        /// Absolute path of the provisioned file holding the signals token (64 hex characters, mode 0600). Not the operator token.
        #[arg(long = "signals-token-file", env = "RISK_GUARD_SIGNALS_TOKEN_FILE")]
        signals_token_file: Option<PathBuf>,
        /// Record every signal and answer it, but quarantine nothing. Start here, then turn it off.
        #[arg(long = "signals-dry-run", env = "RISK_GUARD_SIGNALS_DRY_RUN")]
        signals_dry_run: bool,
        /// At most this many signals applied per minute.
        #[arg(
            long = "signals-max-per-minute",
            env = "RISK_GUARD_SIGNALS_MAX_PER_MINUTE",
            default_value_t = 10
        )]
        signals_max_per_minute: u32,
        /// At most this many workloads held in quarantine by signals at once.
        #[arg(
            long = "signals-max-active",
            env = "RISK_GUARD_SIGNALS_MAX_ACTIVE",
            default_value_t = 5
        )]
        signals_max_active: u32,
        /// Allow the signals listener off loopback over plain HTTP (fence it with a network policy; see docs/siem-signals.md).
        #[arg(
            long = "signals-allow-plaintext",
            env = "RISK_GUARD_SIGNALS_ALLOW_PLAINTEXT"
        )]
        signals_allow_plaintext: bool,
        /// Serve the signals listener over mutual TLS and accept only this exact SPIFFE ID (repeatable). No token is used. Needs --tls-cert, --tls-key and a trust bundle
        /// (--signals-client-bundle, or --svid-bundle) and --svid-trust-domain.
        #[arg(
            long = "signals-allow-spiffe",
            env = "RISK_GUARD_SIGNALS_ALLOW_SPIFFE",
            value_delimiter = ','
        )]
        signals_allow_spiffe: Vec<String>,
        /// The SPIRE trust bundle that client certificates must chain to (default: --svid-bundle).
        #[arg(
            long = "signals-client-bundle",
            env = "RISK_GUARD_SIGNALS_CLIENT_BUNDLE"
        )]
        signals_client_bundle: Option<PathBuf>,
        /// Base URL of an OpenTelemetry Collector's OTLP/HTTP receiver (e.g. http://otel-collector.siem:4318). When given, Risk Guard sends its refusals,
        /// tunnel refusals and signals there as OCSF events carrying the workload, run, task, score and reason.
        #[arg(long = "ocsf-otlp-endpoint", env = "RISK_GUARD_OCSF_OTLP_ENDPOINT")]
        ocsf_otlp_endpoint: Option<String>,
        /// The trust domain that gives sandboxes SPIFFE IDs, used to fill the events' `actor.user.uid`.
        #[arg(long = "ocsf-trust-domain", env = "RISK_GUARD_OCSF_TRUST_DOMAIN")]
        ocsf_trust_domain: Option<String>,
    },
    /// Evaluate one request as the workload that owns an X.509-SVID, against a running SVID listener, and print the decision.
    SvidProbe {
        #[arg(long, default_value = "https://risk-guard.openshell.svc:50062")]
        endpoint: String,
        /// CA certificate that signed the listener's server certificate.
        #[arg(long)]
        server_ca: PathBuf,
        /// DNS name on the listener's certificate, when the endpoint is an IP address.
        #[arg(long)]
        server_name: Option<String>,
        /// The SVID certificate chain and its private key, as spiffe-helper writes them.
        #[arg(long)]
        svid: PathBuf,
        #[arg(long)]
        svid_key: PathBuf,
        #[arg(long, default_value = "GET")]
        method: String,
        #[arg(long, default_value = "api.example.internal")]
        host: String,
        #[arg(long, default_value_t = 443)]
        port: u16,
        #[arg(long, default_value = "/status")]
        path: String,
    },
    /// Check that a running sidecar is serving, over TLS (for Kubernetes exec probes; exit 0 only if SERVING).
    HealthCheck {
        #[arg(long, default_value = "https://127.0.0.1:50061")]
        endpoint: String,
        /// CA certificate that signed the sidecar's certificate.
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        /// DNS name on the sidecar's certificate, when the endpoint is an IP address.
        #[arg(long)]
        server_name: Option<String>,
        #[arg(long, default_value_t = 3)]
        timeout_secs: u64,
        /// What to check: empty is readiness (the decision store answers); `liveness` is the process alone, with no database access.
        #[arg(long, default_value = "")]
        service: String,
    },
    /// Generate a local-test CA, server certificate/key and resource HMAC key (never overwrites).
    LocalSecretsGenerate {
        #[arg(long)]
        out_dir: PathBuf,
        /// Subject alternative name the gateway and supervisors will dial (IP or DNS); repeatable.
        #[arg(long = "san", required = true)]
        sans: Vec<String>,
    },
    /// List an agent's or sandbox's stored restrictions and whether each still blocks.
    RestrictionList {
        #[arg(long)]
        db: PathBuf,
        #[arg(
            long,
            conflicts_with = "sandbox_id",
            required_unless_present = "sandbox_id"
        )]
        agent_id: Option<String>,
        #[arg(long)]
        sandbox_id: Option<String>,
        #[arg(long, requires = "agent_id")]
        context_id: Option<String>,
    },
    /// Quarantine a workload: its sandboxes get no network tunnels through the egress proxy, whatever the scoring says. Audited.
    WorkloadQuarantine {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        reason: String,
    },
    /// End a workload's quarantine. Audited.
    WorkloadRelease {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        reason: String,
        /// With two-person approval on, the only way to release without a second person. Recorded as break-glass in the audit trail.
        #[arg(long)]
        break_glass: bool,
    },
    /// Turn on two-person approval: releasing a quarantine and clearing a restriction then need a proposer and a different approver.
    TwoPersonEnable {
        #[arg(long)]
        db: PathBuf,
    },
    /// Ask for a loosening (release_quarantine, clear_restriction, disable_two_person). Someone else must approve it.
    ChangePropose {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        kind: String,
        /// The workload (ignored for disable_two_person).
        #[arg(long, default_value = "two-person-rule")]
        agent_id: String,
        /// For clear_restriction: the exact scope shown by `restriction-list`.
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        context_id: Option<String>,
        #[arg(long)]
        proposer: String,
        #[arg(long)]
        reason: String,
    },
    /// Approve or reject a request. Approving your own is refused.
    ChangeDecide {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        decider: String,
        #[arg(long, conflicts_with = "reject", required_unless_present = "reject")]
        approve: bool,
        #[arg(long)]
        reject: bool,
        #[arg(long)]
        reason: String,
    },
    /// List change requests, newest first.
    ChangeList {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Write one agent's scoring context (its history, baselines and guardrail revisions) as a portable replay bundle.
    ReplayExport {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
        /// Defaults to the agent's newest scoring context.
        #[arg(long)]
        context_id: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Take a verified snapshot of the decision database (safe while Risk Guard runs): integrity-checked, with a SHA-256 file beside it.
    Backup {
        #[arg(long)]
        db: PathBuf,
        /// The new backup file; it must not exist.
        #[arg(long)]
        out: PathBuf,
    },
    /// Check a backup file against its checksum and its integrity, without touching any database.
    BackupVerify {
        #[arg(long)]
        file: PathBuf,
    },
    /// Replace the decision database with a verified backup. Stop Risk Guard first. Everything decided since the backup is lost.
    Restore {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        db: PathBuf,
        /// Replace an existing database.
        #[arg(long)]
        force: bool,
    },
    /// Replay a bundle from nothing and report whether the same decisions and reason codes come out. Exits non-zero if they do not.
    ReplayVerify {
        #[arg(long)]
        bundle: PathBuf,
        /// Replay even if the bundle says its history is incomplete (the result is then a best effort).
        #[arg(long)]
        allow_incomplete: bool,
    },
    /// List tunnels opened by sandboxes whose supervisors had gone quiet (the silent-supervisor check), newest first.
    SupervisorSilenceList {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// List the quarantined workloads.
    WorkloadQuarantineList {
        #[arg(long)]
        db: PathBuf,
    },
    /// Clear one restriction after review; recorded with operator and reason, never broadens OpenShell policy.
    RestrictionClear {
        #[arg(long)]
        db: PathBuf,
        #[arg(
            long,
            conflicts_with = "sandbox_id",
            required_unless_present = "sandbox_id"
        )]
        agent_id: Option<String>,
        #[arg(long)]
        sandbox_id: Option<String>,
        #[arg(long, requires = "agent_id")]
        context_id: Option<String>,
        /// Exact scope string as shown by `restriction-list`.
        #[arg(long)]
        scope: String,
        /// Who reviewed and cleared it.
        #[arg(long)]
        operator: String,
        /// Why it was a false positive or no longer applies.
        #[arg(long)]
        reason: String,
        /// With two-person approval on, the only way to clear without a second person. Recorded as break-glass in the audit trail.
        #[arg(long)]
        break_glass: bool,
    },
    /// Register a workload ID: an operator-assigned label for a logical agent workload, not a credential.
    /// Use --workspace to bind it only from sandboxes created in that OpenShell workspace.
    AgentRegister {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        display_name: String,
        /// Only sandboxes created in this OpenShell workspace may bind to the workload.
        /// Without it the workload is unscoped and any workspace's sandbox can use the label.
        #[arg(long)]
        workspace: Option<String>,
    },
    /// Change the name people see for an agent (dashboards, SIEM events). The agent_id, which decisions are keyed on, does not change.
    AgentRename {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        display_name: String,
    },
    /// The SIEM's side of the signals path: takes the alert webhook and forwards a quarantine signal to Risk Guard over mutual TLS with its own SVID.
    /// The webhook token comes from the RISK_GUARD_FORWARDER_TOKEN environment variable.
    SignalForwarder {
        #[arg(long, default_value = "0.0.0.0:8088")]
        listen: SocketAddr,
        #[arg(
            long,
            default_value = "https://risk-guard.openshell.svc:50063/v1/signals"
        )]
        target: String,
        /// The SVID certificate chain and key that spiffe-helper keeps current.
        #[arg(long, default_value = "/certs/svid.pem")]
        svid: PathBuf,
        #[arg(long, default_value = "/certs/svid_key.pem")]
        svid_key: PathBuf,
        /// The CA that signed Risk Guard's server certificate.
        #[arg(long)]
        server_ca: PathBuf,
    },
    /// The SIEM's feature publisher: every --interval it asks OpenSearch (read-only) what OpenShell and Risk Guard recorded and posts one batch of risk features to
    /// Risk Guard's /features over mutual TLS, with the same SVID files as the signal forwarder. See docs/siem-features-publisher.md.
    FeaturePublisher {
        /// The full URL of Risk Guard's feature endpoint.
        #[arg(
            long,
            default_value = "https://risk-guard.openshell.svc:50063/features"
        )]
        target: String,
        #[arg(long, default_value = "/certs/svid.pem")]
        svid: PathBuf,
        #[arg(long, default_value = "/certs/svid_key.pem")]
        svid_key: PathBuf,
        /// The CA that signed Risk Guard's server certificate (not needed with --dry-run).
        #[arg(long, required_unless_present = "dry_run")]
        server_ca: Option<PathBuf>,
        #[arg(
            long,
            default_value = "https://opensearch-cluster-master.siem.svc:9200"
        )]
        opensearch_url: String,
        /// Files holding the read-only OpenSearch user name and password (a mounted Secret). They are read on every interval.
        #[arg(long)]
        opensearch_user_file: PathBuf,
        #[arg(long)]
        opensearch_password_file: PathBuf,
        /// A CA to trust for OpenSearch's certificate.
        #[arg(long)]
        opensearch_ca: Option<PathBuf>,
        /// Demo only: do not verify OpenSearch's self-signed certificate.
        #[arg(long)]
        opensearch_insecure: bool,
        /// The SPIFFE trust domain of the sandboxes' IDs; with it each sandbox's features are also sent under its SPIFFE ID.
        #[arg(long)]
        trust_domain: Option<String>,
        /// Take the trust domain from this pod's own SVID instead (the publisher and the sandboxes are issued by the same SPIRE).
        #[arg(long)]
        trust_domain_from_svid: bool,
        /// Seconds between batches (at least 10: Risk Guard accepts one batch per 10 seconds per sender).
        #[arg(long, default_value_t = 30)]
        interval: u64,
        /// Run the queries once, print the batch that would be posted (and any query that failed) and exit. Posts nothing, needs no SVID.
        #[arg(long)]
        dry_run: bool,
    },
    /// Create a run pinned to an agent revision, approved baseline and scoring context.
    RunCreate {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        agent_revision: String,
        #[arg(long)]
        task_profile: String,
        #[arg(long, default_value = "enforce")]
        mode: String,
    },
    /// Bind a pristine sandbox epoch to a run through the trusted operator path.
    RunBind {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        sandbox_id: String,
        #[arg(long, default_value = "local-gateway")]
        gateway_id: String,
    },
    /// End a run without clearing shared agent scoring state.
    RunEnd {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        run_id: String,
    },
    /// Inspect saved per-agent guardrails and recorded application status.
    GuardrailsShow {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
    },
    /// Export saved guardrails into a policy for a NEW sandbox, never a hot filesystem update.
    GuardrailsExport {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Inspect actual native learning evidence, frozen models and promotion gates.
    AdaptiveShow {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
    },
    /// Apply an explicit adaptive lifecycle operation from a typed JSON file.
    AdaptiveApply {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        request: PathBuf,
    },
    /// Import an operator-approved baseline artifact; never learns from live traffic.
    BaselineImport {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Write a task profile's approved routes and deny list into a copy of a sandbox policy as OpenShell rules, and check the result is no wider. Applies nothing.
    PolicyExport {
        /// The task profile's baseline JSON.
        #[arg(long)]
        baseline: PathBuf,
        /// The sandbox policy YAML to start from. Its risk-guard middleware says which hosts the profile covers.
        #[arg(long)]
        policy: PathBuf,
        /// `audit` logs violations and allows the request (default); `enforce` blocks.
        #[arg(long, default_value = "audit")]
        enforcement: String,
        /// A reviewed file of demo exceptions (extra allow rules) to add. DEMO ONLY: the result is deliberately wider than the baseline, and its rule name says so.
        #[arg(long)]
        demo_exceptions: Option<PathBuf>,
        /// Write the policy here (otherwise it is printed after the summary).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Create or activate a sandbox epoch in the risk store.
    EpochCreate {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        sandbox_id: String,
        #[arg(long, default_value = "local-gateway")]
        gateway_id: String,
        #[arg(long)]
        epoch_id: Option<String>,
        #[arg(long, default_value = "repo-triage-readonly")]
        task_profile: String,
        #[arg(long, default_value = "enforce")]
        mode: String,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Inspect recent behavioral risk evaluations for a sandbox.
    DecisionInspect {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        sandbox_id: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Generate a prover-verified monotonic policy-hardening report for a sandbox.
    HardeningReport {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        sandbox_id: String,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Evaluate a single HTTP request through the Rust normalizer, detector, and SQLite store.
    EvaluateRequest {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        sandbox_id: String,
        #[arg(long)]
        request_id: String,
        #[arg(long, default_value = "https")]
        scheme: String,
        #[arg(long, default_value = "api.github.local")]
        host: String,
        #[arg(long, default_value_t = 18443)]
        port: u16,
        #[arg(long)]
        method: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        binary: Option<String>,
        /// The same resource HMAC key file the sidecar serves with.
        #[arg(long, env = "RISK_GUARD_HMAC_KEY_FILE")]
        hmac_key_file: Option<PathBuf>,
        /// The same API semantic map the sidecar serves with.
        #[arg(long, env = "RISK_GUARD_API_SEMANTICS")]
        api_semantics: Option<PathBuf>,
        #[arg(long)]
        allow_insecure_local_test: bool,
    },
    /// Serve loopback-only evidence, optionally enabling authenticated guardrail edits.
    Dashboard {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        #[arg(long)]
        db: PathBuf,
        /// Enable operator writes using an owner-only runtime capability token.
        #[arg(long)]
        operator_token_file: Option<PathBuf>,
        /// Require Microsoft Entra sign-in. Tenant and app (client) ID of the console's app registration.
        #[arg(long, env = "RISK_GUARD_ENTRA_TENANT_ID", requires = "entra_client_id")]
        entra_tenant_id: Option<String>,
        #[arg(long, env = "RISK_GUARD_ENTRA_CLIENT_ID", requires = "entra_tenant_id")]
        entra_client_id: Option<String>,
        /// Object IDs of accounts that may read and change settings (repeat or comma-separate).
        #[arg(
            long = "entra-admin-oid",
            env = "RISK_GUARD_ENTRA_ADMIN_OIDS",
            value_delimiter = ','
        )]
        entra_admin_oids: Vec<String>,
        /// Object IDs of accounts that may read only.
        #[arg(
            long = "entra-viewer-oid",
            env = "RISK_GUARD_ENTRA_VIEWER_OIDS",
            value_delimiter = ','
        )]
        entra_viewer_oids: Vec<String>,
        /// Also require a listed account to read. Off by default: the public console is readable by anyone and only
        /// administrators (who sign in at /admin) can change settings.
        #[arg(long, env = "RISK_GUARD_ENTRA_REQUIRE_SIGN_IN_TO_READ")]
        entra_require_sign_in_to_read: bool,
    },
    /// Run the synthetic integration harness (not a native OpenShell deployment).
    DemoDashboard {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: SocketAddr,
        #[arg(long, default_value = "/tmp/openshell-live-dashboard.db")]
        db: PathBuf,
    },
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Resolve on Ctrl-C or, for container runtimes, SIGTERM so in-flight decision
/// transactions finish before the sidecar exits.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received; draining gRPC server");
}

/// Build the normalizer from a mounted semantic map, or the built-in demo map.
fn load_normalizer(api_semantics: Option<&Path>, hmac_key: &[u8]) -> Result<CanonicalNormalizer> {
    match api_semantics {
        Some(path) => {
            let normalizer = CanonicalNormalizer::from_file(path, hmac_key)?;
            let digest = sha256_hex(&std::fs::read(path).unwrap_or_default());
            tracing::info!(path = %path.display(), sha256 = %digest, "loaded mounted api semantics");
            Ok(normalizer)
        }
        None => {
            tracing::warn!(
                "using the built-in demo api semantics (GitHub-style routes, host-agnostic)"
            );
            Ok(CanonicalNormalizer::new_default(hmac_key))
        }
    }
}

fn restriction_target<'a>(
    agent_id: Option<&'a str>,
    sandbox_id: Option<&'a str>,
    context_id: Option<&'a str>,
) -> Result<crate::store::RestrictionTarget<'a>> {
    match (agent_id, sandbox_id) {
        (Some(agent_id), None) => Ok(crate::store::RestrictionTarget::Agent {
            agent_id,
            context_id,
        }),
        (None, Some(sandbox_id)) => Ok(crate::store::RestrictionTarget::Sandbox { sandbox_id }),
        _ => Err(RiskGuardError::InvalidArgument(
            "pass exactly one of --agent-id or --sandbox-id".into(),
        )),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn parse_mode(raw: &str) -> Result<EnforcementMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "enforce" => Ok(EnforcementMode::Enforce),
        "observe" => Ok(EnforcementMode::Observe),
        other => Err(RiskGuardError::InvalidArgument(format!(
            "invalid enforcement mode '{other}'; expected 'observe' or 'enforce'"
        ))),
    }
}

/// Open a SQLite risk store at `db` and seed the standard baseline profiles from
/// [`build_standard_corpus`] if `repo-triage-readonly` is not yet present.
pub fn open_and_seed_store(db: impl AsRef<Path>) -> Result<SqliteRiskStore> {
    let store = SqliteRiskStore::open(db)?;
    if store.get_baseline(PROFILE_REPO_TRIAGE_READONLY)?.is_none() {
        let corpus = build_standard_corpus();
        store.store_baseline(&corpus.default_baseline)?;
        store.store_baseline(&corpus.maintenance_baseline)?;
        store.store_baseline(&corpus.cold_start_baseline)?;
        for profile in corpus.baselines.values() {
            store.store_baseline(profile)?;
        }
    }
    Ok(store)
}

/// Execute a parsed [`Cli`] command and return its JSON output.
pub async fn execute_cli(cli: Cli) -> Result<String> {
    match cli.command {
        Commands::Serve {
            listen,
            db,
            gateway_id,
            audience,
            public_key_pem,
            allow_insecure_local_test,
            default_task_profile,
            allow_unattributed,
            tls_cert,
            tls_key,
            hmac_key_file,
            api_semantics,
            agent_binding_principals,
            auto_register_agents,
            workload_from_principal,
            allow_local_dev_principal,
            decision_retention_days,
            svid_listen,
            svid_bundle,
            svid_trust_domains,
            svid_proxy_ids,
            tunnel_pod_namespace,
            tunnel_restriction_mode,
            tunnel_silence_seconds,
            signals_listen,
            signals_token_file,
            signals_dry_run,
            signals_max_per_minute,
            signals_max_active,
            signals_allow_plaintext,
            signals_allow_spiffe,
            signals_client_bundle,
            ocsf_otlp_endpoint,
            ocsf_trust_domain,
        } => {
            if public_key_pem.is_none() && !allow_insecure_local_test {
                return Err(RiskGuardError::InvalidArgument(
                    "--public-key-pem is required unless --allow-insecure-local-test is explicitly enabled".to_string(),
                ));
            }
            let tls = crate::sidecar::listener_tls(
                listen,
                tls_cert.as_deref(),
                tls_key.as_deref(),
                allow_insecure_local_test,
            )?;
            let hmac_key = crate::sidecar::resource_hmac_key(
                hmac_key_file.as_deref(),
                allow_insecure_local_test,
            )?;
            let store = Arc::new(SqliteRiskStore::open(&db)?);
            let svid_store = Arc::clone(&store) as Arc<dyn RiskStore>;
            store.bind_resource_key(&hmac_key, now_unix_ms())?;
            store.record_runtime_facts(
                &[
                    ("tunnel_restriction_mode", tunnel_restriction_mode.as_str()),
                    (
                        "tunnel_gate",
                        if svid_proxy_ids.is_empty() {
                            "off"
                        } else {
                            "on"
                        },
                    ),
                    (
                        "signals_listening",
                        if signals_listen.is_some() { "1" } else { "0" },
                    ),
                    ("signals_dry_run", if signals_dry_run { "1" } else { "0" }),
                ],
                now_unix_ms(),
            )?;
            if decision_retention_days > 0 {
                let retention_store = Arc::clone(&store);
                let window_ms = i64::from(decision_retention_days) * 86_400_000;
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
                    loop {
                        tick.tick().await;
                        let store = Arc::clone(&retention_store);
                        let cutoff = now_unix_ms().saturating_sub(window_ms);
                        match tokio::task::spawn_blocking(move || {
                            store.prune_decisions_older_than(cutoff)
                        })
                        .await
                        {
                            Ok(Ok(0)) => {}
                            Ok(Ok(deleted)) => tracing::info!(
                                deleted,
                                retention_days = decision_retention_days,
                                "pruned decisions past the retention window"
                            ),
                            Ok(Err(err)) => {
                                tracing::warn!(error = %err, "decision retention pruning failed")
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "decision retention task failed")
                            }
                        }
                    }
                });
                tracing::info!(
                    retention_days = decision_retention_days,
                    "decision retention is enabled"
                );
            }
            if store.get_baseline(&default_task_profile)?.is_none() {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "baseline '{default_task_profile}' is not provisioned; use baseline-import"
                )));
            }

            let verifier = if let Some(pem_path) = public_key_pem {
                let pem_bytes = std::fs::read(&pem_path).map_err(|err| {
                    RiskGuardError::InvalidArgument(format!(
                        "failed to read public_key_pem '{}': {err}",
                        pem_path.display()
                    ))
                })?;
                JwtAuthVerifier::from_ed25519_pem(&gateway_id, &audience, &pem_bytes)?
                    .with_allow_insecure_local_test(allow_insecure_local_test)
            } else {
                JwtAuthVerifier::insecure_for_local_test(&gateway_id, &audience)
                    .with_allow_insecure_local_test(allow_insecure_local_test)
            };

            let auth: Arc<dyn AuthVerifier> = Arc::new(verifier);
            let normalizer = Arc::new(load_normalizer(api_semantics.as_deref(), &hmac_key)?);
            let detector = Arc::new(InteractionRiskDetector::new_default());
            let hardening = Arc::new(ProverHardeningEngine::new());
            let health = crate::sidecar::HealthServer::new(Arc::clone(&store));

            let ocsf = ocsf_otlp_endpoint.map(|endpoint| {
                crate::ocsf::OcsfEmitter::start(
                    crate::ocsf::OcsfConfig {
                        endpoint,
                        trust_domain: ocsf_trust_domain.clone(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    },
                    Arc::clone(&store),
                )
            });
            if let (Some(signals_addr), false) = (signals_listen, signals_allow_spiffe.is_empty()) {
                // Mutual TLS: the sender is the SPIFFE ID in its certificate. No shared secret.
                let (Some(cert), Some(key)) = (tls_cert.as_deref(), tls_key.as_deref()) else {
                    return Err(RiskGuardError::InvalidArgument(
                        "--signals-allow-spiffe needs --tls-cert and --tls-key (the server identity)".into(),
                    ));
                };
                let Some(bundle) = signals_client_bundle
                    .clone()
                    .or_else(|| svid_bundle.clone())
                else {
                    return Err(RiskGuardError::InvalidArgument(
                        "--signals-allow-spiffe needs a trust bundle (--signals-client-bundle or --svid-bundle)".into(),
                    ));
                };
                let policy = crate::store::SignalPolicy {
                    dry_run: signals_dry_run,
                    max_per_minute: signals_max_per_minute,
                    max_active: signals_max_active,
                    ..Default::default()
                };
                let mut state = crate::signals::SignalsState::new_spiffe(
                    Arc::clone(&store),
                    &svid_trust_domains,
                    &signals_allow_spiffe,
                    policy,
                )?;
                if let Some(emitter) = &ocsf {
                    state = state.with_ocsf(Arc::clone(emitter));
                }
                let (cert, key) = (
                    std::fs::read(cert)
                        .map_err(|e| RiskGuardError::InvalidArgument(format!("--tls-cert: {e}")))?,
                    std::fs::read(key)
                        .map_err(|e| RiskGuardError::InvalidArgument(format!("--tls-key: {e}")))?,
                );
                tokio::spawn(async move {
                    if let Err(error) = crate::signals::serve_mtls(
                        signals_addr,
                        state,
                        cert,
                        key,
                        bundle,
                        shutdown_signal,
                    )
                    .await
                    {
                        tracing::error!(%error, "the signals listener stopped");
                    }
                });
            } else {
                match (signals_listen, signals_token_file.as_deref()) {
                    (Some(signals_addr), token_file) => {
                        let policy = crate::store::SignalPolicy {
                            dry_run: signals_dry_run,
                            max_per_minute: signals_max_per_minute,
                            max_active: signals_max_active,
                            ..Default::default()
                        };
                        let state = match token_file {
                            Some(file) => crate::signals::SignalsState::from_token_file(
                                Arc::clone(&store),
                                file,
                                policy,
                            )?,
                            None => {
                                crate::signals::SignalsState::from_env(Arc::clone(&store), policy)?
                            }
                        };
                        let state = match &ocsf {
                            Some(emitter) => state.with_ocsf(Arc::clone(emitter)),
                            None => state,
                        };
                        tokio::spawn(async move {
                            if let Err(error) =
                                crate::signals::serve(signals_addr, state, signals_allow_plaintext)
                                    .await
                            {
                                tracing::error!(%error, "the signals listener stopped");
                            }
                        });
                    }
                    (None, None) => {}
                    (None, Some(_)) => {
                        return Err(RiskGuardError::InvalidArgument(
                            "--signals-token-file has no effect without --signals-listen".into(),
                        ));
                    }
                }
            }

            // Decision time is accumulated in memory and flushed to SQLite every 30 seconds, off the request path.
            let latency = Arc::new(crate::latency::LatencyRecorder::default());
            {
                let latency = Arc::clone(&latency);
                let latency_store = Arc::clone(&store);
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                    loop {
                        tick.tick().await;
                        let interval = latency.take();
                        if interval.count == 0 {
                            continue;
                        }
                        let store = Arc::clone(&latency_store);
                        match tokio::task::spawn_blocking(move || {
                            store.record_latency_interval(now_unix_ms(), &interval)
                        })
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                tracing::warn!(error = %err, "recording decision latency failed")
                            }
                            Err(err) => {
                                tracing::warn!(error = %err, "decision latency task failed")
                            }
                        }
                    }
                });
            }
            let middleware_service = RiskGuardMiddlewareService::new(
                Arc::clone(&auth),
                normalizer,
                detector,
                Arc::clone(&store) as Arc<dyn RiskStore>,
                audience.clone(),
            )
            .with_required_agent_identity(!allow_unattributed)
            .with_latency_recorder(latency);
            let middleware_service = match &ocsf {
                Some(emitter) => middleware_service.with_ocsf(Arc::clone(emitter)),
                None => middleware_service,
            };

            if let Some(svid_addr) = svid_listen {
                let (Some(bundle), Some(server_tls)) = (svid_bundle.clone(), tls.clone()) else {
                    return Err(RiskGuardError::InvalidArgument(
                        "--svid-listen needs --svid-bundle and a server identity (--tls-cert and --tls-key)".into(),
                    ));
                };
                let policy = crate::spiffe::SvidPolicy::new(&svid_trust_domains)?;
                let enroller = Arc::new(crate::spiffe::SvidEnroller::new(
                    Arc::clone(&svid_store),
                    gateway_id.clone(),
                    default_task_profile.clone(),
                ));
                let mut svid_service = middleware_service.clone();
                svid_service.auth = Arc::new(crate::spiffe::SvidAuthVerifier::with_enroller(
                    policy.clone(),
                    Arc::clone(&enroller),
                ));
                let ext_authz = if svid_proxy_ids.is_empty() {
                    None
                } else {
                    let mut service = crate::ext_authz::ExtAuthzService::new(
                        Arc::clone(&svid_store),
                        Arc::clone(&middleware_service.normalizer),
                        Arc::clone(&middleware_service.detector),
                        enroller,
                        policy.clone(),
                        &svid_proxy_ids,
                    )?;
                    service = service.with_restriction_mode(match tunnel_restriction_mode.as_str() {
                        "shadow" => crate::ext_authz::TunnelMode::Shadow,
                        "enforce" => crate::ext_authz::TunnelMode::Enforce,
                        other => {
                            return Err(RiskGuardError::InvalidArgument(format!(
                                "--tunnel-restriction-mode must be shadow or enforce, not '{other}'"
                            )));
                        }
                    });
                    if let Some(emitter) = &ocsf {
                        service = service.with_ocsf(Arc::clone(emitter));
                    }
                    service = service.with_silence_threshold(std::time::Duration::from_secs(
                        tunnel_silence_seconds,
                    ));
                    if let Some(namespace) = &tunnel_pod_namespace {
                        service = service.with_tunnel_resolver(Arc::new(
                            crate::pod_resolver::KubePodResolver::in_cluster(namespace)?,
                        ));
                    }
                    Some(service)
                };
                tokio::spawn(async move {
                    if let Err(error) = crate::spiffe::serve_svid_listener(
                        svid_addr,
                        server_tls,
                        bundle,
                        policy,
                        svid_service,
                        ext_authz,
                        shutdown_signal,
                    )
                    .await
                    {
                        tracing::error!(%error, "the SVID listener stopped");
                    }
                });
            } else if svid_bundle.is_some()
                || !svid_trust_domains.is_empty()
                || !svid_proxy_ids.is_empty()
                || tunnel_pod_namespace.is_some()
            {
                return Err(RiskGuardError::InvalidArgument(
                    "--svid-bundle and --svid-trust-domain have no effect without --svid-listen"
                        .into(),
                ));
            }

            let agent_binding = crate::interceptor_service::AgentBindingPolicy::new(
                &agent_binding_principals,
                auto_register_agents,
            )?
            .with_principal_derivation(workload_from_principal)
            .with_local_dev_principals(allow_local_dev_principal);
            if agent_binding.is_enabled() {
                tracing::info!(
                    principals = agent_binding_principals.len(),
                    auto_register_agents,
                    workload_from_principal,
                    "workload binding is enabled"
                );
            }
            let interceptor_service = RiskGuardInterceptorService::new(
                auth,
                store as Arc<dyn RiskStore>,
                hardening,
                gateway_id,
                audience,
                default_task_profile,
            )
            .with_agent_binding(agent_binding);

            tracing::info!(%listen, db = %db.display(), tls = tls.is_some(), "starting openshell-risk-guard gRPC server");

            let mut server = tonic::transport::Server::builder();
            if let Some(tls) = tls {
                server = server.tls_config(tls).map_err(|err| {
                    RiskGuardError::InvalidArgument(format!("invalid TLS identity: {err}"))
                })?;
            }
            server
                .add_service(health)
                .add_service(middleware_service.into_server())
                .add_service(interceptor_service.into_server())
                .serve_with_shutdown(listen, shutdown_signal())
                .await
                .map_err(|err| RiskGuardError::Internal(format!("gRPC server error: {err}")))?;

            Ok(serde_json::json!({
                "status": "stopped",
                "listen": listen.to_string(),
            })
            .to_string())
        }

        Commands::AgentRename {
            db,
            agent_id,
            display_name,
        } => {
            SqliteRiskStore::open(db)?.rename_agent(&agent_id, &display_name)?;
            Ok(serde_json::json!({"agent_id": agent_id, "display_name": display_name, "status": "renamed"}).to_string())
        }

        Commands::AgentRegister {
            db,
            agent_id,
            display_name,
            workspace,
        } => {
            let store = SqliteRiskStore::open(db)?;
            match &workspace {
                Some(workspace) => {
                    store.register_agent_in_workspace(&agent_id, &display_name, workspace)?
                }
                None => store.register_agent(&agent_id, &display_name)?,
            }
            Ok(serde_json::json!({"agent_id": agent_id, "workspace": workspace, "status": "registered"}).to_string())
        }
        Commands::RunCreate {
            db,
            agent_id,
            run_id,
            agent_revision,
            task_profile,
            mode,
        } => {
            SqliteRiskStore::open(db)?.create_agent_run(
                &agent_id,
                &run_id,
                &agent_revision,
                &task_profile,
                parse_mode(&mode)?,
            )?;
            Ok(
                serde_json::json!({"agent_id": agent_id, "run_id": run_id, "status": "created"})
                    .to_string(),
            )
        }
        Commands::RunBind {
            db,
            run_id,
            sandbox_id,
            gateway_id,
        } => {
            SqliteRiskStore::open(db)?.bind_agent_run(&run_id, &sandbox_id, &gateway_id)?;
            Ok(
                serde_json::json!({"run_id": run_id, "sandbox_id": sandbox_id, "status": "bound"})
                    .to_string(),
            )
        }
        Commands::RunEnd { db, run_id } => {
            SqliteRiskStore::open(db)?.end_agent_run(&run_id)?;
            Ok(serde_json::json!({"run_id": run_id, "status": "ended"}).to_string())
        }
        Commands::GuardrailsShow { db, agent_id } => {
            let view = SqliteRiskStore::open(db)?
                .agent_guardrails(&agent_id, now_unix_ms())?
                .ok_or_else(|| RiskGuardError::InvalidArgument("workload not found".into()))?;
            Ok(serde_json::to_string_pretty(&view)?)
        }
        Commands::GuardrailsExport { db, agent_id, out } => {
            let yaml = SqliteRiskStore::open(db)?
                .export_agent_guardrails_policy(&agent_id)?
                .ok_or_else(|| {
                    RiskGuardError::InvalidArgument("workload has no saved guardrails".into())
                })?;
            if let Some(path) = out {
                std::fs::write(&path, yaml).map_err(|error| {
                    RiskGuardError::InvalidArgument(format!(
                        "cannot write exported policy '{}': {error}",
                        path.display()
                    ))
                })?;
                Ok(serde_json::json!({"status":"exported","path":path}).to_string())
            } else {
                Ok(yaml)
            }
        }
        Commands::AdaptiveShow { db, agent_id } => {
            let view = SqliteRiskStore::open(db)?
                .agent_adaptive(&agent_id, now_unix_ms())?
                .ok_or_else(|| RiskGuardError::InvalidArgument("workload not found".into()))?;
            Ok(serde_json::to_string_pretty(&view)?)
        }
        Commands::AdaptiveApply {
            db,
            agent_id,
            request,
        } => {
            let file = std::fs::File::open(&request).map_err(|error| {
                RiskGuardError::InvalidArgument(format!(
                    "cannot read adaptive request '{}': {error}",
                    request.display()
                ))
            })?;
            if file
                .metadata()
                .map_err(|error| RiskGuardError::InvalidArgument(error.to_string()))?
                .len()
                > 65_536
            {
                return Err(RiskGuardError::InvalidArgument(
                    "adaptive request exceeds 64 KiB".into(),
                ));
            }
            let operation: crate::adaptive_controls::AdaptiveOperation =
                serde_json::from_reader(file)?;
            match SqliteRiskStore::open(db)?.apply_adaptive_operation(
                &agent_id,
                &operation,
                "local-cli",
                now_unix_ms(),
            )? {
                crate::adaptive_controls::AdaptiveUpdateResult::Applied(view) => {
                    Ok(serde_json::to_string_pretty(&view)?)
                }
                crate::adaptive_controls::AdaptiveUpdateResult::Conflict(message) => {
                    Err(RiskGuardError::Policy(message))
                }
            }
        }
        Commands::PolicyExport {
            baseline,
            policy,
            enforcement,
            demo_exceptions,
            out,
        } => {
            let baseline = load_baseline_profile(&baseline)?;
            let demo = demo_exceptions
                .as_deref()
                .map(crate::policy_export::DemoExceptions::load)
                .transpose()?;
            let base = std::fs::read_to_string(&policy).map_err(|err| {
                RiskGuardError::InvalidArgument(format!(
                    "failed to read policy '{}': {err}",
                    policy.display()
                ))
            })?;
            let export = crate::policy_export::export_policy_with_demo_exceptions(
                &baseline,
                &base,
                &enforcement,
                demo.as_ref(),
            )?;
            match out {
                Some(path) => {
                    std::fs::write(&path, &export.yaml).map_err(|err| {
                        RiskGuardError::InvalidArgument(format!(
                            "failed to write '{}': {err}",
                            path.display()
                        ))
                    })?;
                    Ok(export.summary.to_string())
                }
                None => Ok(format!(
                    "{}
---
{}",
                    export.summary, export.yaml
                )),
            }
        }
        Commands::BaselineImport { db, profile } => {
            let baseline = load_baseline_profile(&profile)?;
            if baseline.task_profile.trim().is_empty()
                || baseline.approved_by.trim().is_empty()
                || baseline.version.trim().is_empty()
                || baseline.normalizer_version != crate::normalizer::DEFAULT_NORMALIZER_VERSION
            {
                return Err(RiskGuardError::InvalidArgument(
                    "baseline requires a task profile, approver, version and compatible normalizer_version".to_string(),
                ));
            }
            let store = SqliteRiskStore::open(&db)?;
            let hash = store.store_baseline(&baseline)?;
            Ok(serde_json::json!({
                "task_profile": baseline.task_profile,
                "baseline_hash": hash,
                "maturity": baseline.maturity(),
                "source": "operator_import"
            })
            .to_string())
        }

        Commands::EpochCreate {
            db,
            sandbox_id,
            gateway_id,
            epoch_id,
            task_profile,
            mode,
            policy,
        } => {
            let sandbox_id = sandbox_id.trim().to_string();
            if sandbox_id.is_empty() {
                return Err(RiskGuardError::InvalidArgument(
                    "sandbox_id must not be empty".to_string(),
                ));
            }

            let parsed_mode = parse_mode(&mode)?;
            let store = SqliteRiskStore::open(&db)?;
            let now_ms = now_unix_ms();

            let (resolved_task_profile, baseline_hash) =
                if let Some(profile) = store.get_baseline(&task_profile)? {
                    (
                        profile.task_profile.clone(),
                        compute_baseline_hash(&profile),
                    )
                } else {
                    return Err(RiskGuardError::InvalidArgument(format!(
                        "baseline '{task_profile}' is not provisioned; use baseline-import"
                    )));
                };

            let mut credentialed_endpoints = BTreeSet::new();
            let mut active_policy_hash = None;
            let mut loaded_policy_yaml = None;

            if let Some(policy_path) = policy {
                let policy_yaml = std::fs::read_to_string(&policy_path).map_err(|err| {
                    RiskGuardError::InvalidArgument(format!(
                        "failed to read policy file '{}': {err}",
                        policy_path.display()
                    ))
                })?;
                let hardening = ProverHardeningEngine::new();
                credentialed_endpoints = hardening.extract_credentialed_endpoints(&policy_yaml)?;
                active_policy_hash = Some(sha256_hex(policy_yaml.as_bytes()));
                loaded_policy_yaml = Some(policy_yaml);
            }

            let resolved_epoch_id = epoch_id
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("ep-{sandbox_id}-{now_ms}"));

            let epoch = EpochRecord {
                epoch_id: resolved_epoch_id,
                gateway_id,
                sandbox_id: sandbox_id.clone(),
                task_profile: resolved_task_profile,
                baseline_hash,
                mode: parsed_mode,
                active: true,
                next_sequence: 1,
                created_at_ms: now_ms,
                credentialed_endpoints: credentialed_endpoints.clone(),
                active_policy_hash: active_policy_hash.clone(),
            };

            store.upsert_epoch(&epoch)?;

            if let (Some(policy_yaml), Some(policy_hash)) =
                (loaded_policy_yaml.as_deref(), active_policy_hash.as_deref())
            {
                store.record_policy_snapshot(
                    &sandbox_id,
                    policy_hash,
                    policy_yaml,
                    &credentialed_endpoints,
                    "cli_epoch_create",
                    now_ms,
                )?;
            }

            Ok(serde_json::to_string_pretty(&epoch)?)
        }

        Commands::DecisionInspect {
            db,
            sandbox_id,
            limit,
        } => {
            let store = SqliteRiskStore::open(&db)?;
            let decisions = store.list_decisions(&sandbox_id, limit)?;
            Ok(serde_json::to_string_pretty(&decisions)?)
        }

        Commands::HardeningReport {
            db,
            sandbox_id,
            policy,
            out,
        } => {
            let store = SqliteRiskStore::open(&db)?;
            let current_policy_yaml = std::fs::read_to_string(&policy).map_err(|err| {
                RiskGuardError::InvalidArgument(format!(
                    "failed to read policy file '{}': {err}",
                    policy.display()
                ))
            })?;

            let now_ms = now_unix_ms();
            let active_epoch = store.get_active_epoch(&sandbox_id)?;
            let history = store.list_normalized_requests(&sandbox_id)?;

            let epoch_id = if let Some(ref ep) = active_epoch {
                ep.epoch_id.clone()
            } else if let Some(first_decision) =
                store.list_decisions(&sandbox_id, 1)?.into_iter().next()
            {
                first_decision.epoch_id
            } else {
                format!("ep-{sandbox_id}")
            };

            let (interval_start_ms, interval_end_ms) = if !history.is_empty() {
                let start = history
                    .iter()
                    .map(|(req, _)| req.timestamp_ms)
                    .min()
                    .unwrap_or(now_ms);
                let end = history
                    .iter()
                    .map(|(req, _)| req.timestamp_ms)
                    .max()
                    .unwrap_or(now_ms)
                    .max(start);
                (start, end)
            } else {
                let start = active_epoch.as_ref().map_or(now_ms, |ep| ep.created_at_ms);
                (start, now_ms.max(start))
            };

            let held_out_benign: Vec<_> = history
                .iter()
                .filter_map(|(req, outcome)| {
                    matches!(
                        outcome,
                        DecisionOutcome::Allow | DecisionOutcome::AllowWithObservation
                    )
                    .then_some(req.clone())
                })
                .collect();

            let coverage_gaps: Vec<String> = store
                .list_coverage_gaps(&sandbox_id)?
                .into_iter()
                .map(|(reason, start_ms, end_ms)| format!("{reason} ({start_ms}..{end_ms})"))
                .collect();

            let engine = ProverHardeningEngine::new();
            let candidate = engine.generate_recommendation(
                &sandbox_id,
                &epoch_id,
                &current_policy_yaml,
                &history,
                &held_out_benign,
                interval_start_ms,
                interval_end_ms,
                coverage_gaps,
            )?;

            store.save_recommendation(&candidate)?;

            let report_json = serde_json::to_string_pretty(&candidate)?;
            if let Some(out_path) = out {
                if let Some(parent) = out_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent).map_err(|err| {
                        RiskGuardError::Storage(format!(
                            "failed to create output directory '{}': {err}",
                            parent.display()
                        ))
                    })?;
                }
                std::fs::write(&out_path, &report_json).map_err(|err| {
                    RiskGuardError::Storage(format!(
                        "failed to write hardening report to '{}': {err}",
                        out_path.display()
                    ))
                })?;
            }

            Ok(report_json)
        }

        Commands::EvaluateRequest {
            db,
            sandbox_id,
            request_id,
            scheme,
            host,
            port,
            method,
            path,
            binary,
            hmac_key_file,
            api_semantics,
            allow_insecure_local_test,
        } => {
            let hmac_key = crate::sidecar::resource_hmac_key(
                hmac_key_file.as_deref(),
                allow_insecure_local_test,
            )?;
            let store = SqliteRiskStore::open(&db)?;
            store.bind_resource_key(&hmac_key, now_unix_ms())?;
            let normalizer = load_normalizer(api_semantics.as_deref(), &hmac_key)?;
            let detector = InteractionRiskDetector::new_default();
            let raw = RawRequestInput {
                request_id,
                sandbox_id: sandbox_id.clone(),
                sandbox_name: sandbox_id,
                workspace: "default".to_string(),
                scheme,
                host,
                port,
                method,
                path,
                binary_path: binary,
                pid: None,
                ancestors: vec![],
                timestamp_ms: now_unix_ms(),
            };
            let normalized = normalizer.normalize(&raw)?;
            let evaluation = store.evaluate_and_commit_atomic(&normalized, &detector)?;
            Ok(serde_json::to_string_pretty(&evaluation)?)
        }

        Commands::SvidProbe {
            endpoint,
            server_ca,
            server_name,
            svid,
            svid_key,
            method,
            host,
            port,
            path,
        } => {
            let read = |path: &Path, what: &str| {
                std::fs::read_to_string(path).map_err(|error| {
                    RiskGuardError::InvalidArgument(format!(
                        "cannot read the {what} '{}': {error}",
                        path.display()
                    ))
                })
            };
            let decision = crate::spiffe::probe(&crate::spiffe::ProbeRequest {
                endpoint: &endpoint,
                server_ca_pem: &read(&server_ca, "server CA")?,
                server_name: server_name.as_deref(),
                svid_pem: &read(&svid, "SVID")?,
                svid_key_pem: &read(&svid_key, "SVID key")?,
                method: &method,
                host: &host,
                port,
                path: &path,
            })
            .await?;
            Ok(decision.to_string())
        }

        Commands::HealthCheck {
            endpoint,
            tls_ca,
            server_name,
            timeout_secs,
            service,
        } => {
            crate::sidecar::probe_health_service(
                &endpoint,
                tls_ca.as_deref(),
                server_name.as_deref(),
                std::time::Duration::from_secs(timeout_secs.max(1)),
                &service,
            )
            .await?;
            Ok(serde_json::json!({"status": "SERVING", "endpoint": endpoint}).to_string())
        }

        Commands::LocalSecretsGenerate { out_dir, sans } => {
            let generated = crate::sidecar::generate_local_secrets(&out_dir, &sans)?;
            Ok(serde_json::to_string_pretty(&generated)?)
        }

        Commands::RestrictionList {
            db,
            agent_id,
            sandbox_id,
            context_id,
        } => {
            let target = restriction_target(
                agent_id.as_deref(),
                sandbox_id.as_deref(),
                context_id.as_deref(),
            )?;
            let view = SqliteRiskStore::open(&db)?.list_restrictions(target, now_unix_ms())?;
            Ok(serde_json::to_string_pretty(&view)?)
        }

        Commands::WorkloadQuarantine {
            db,
            agent_id,
            operator,
            reason,
        } => {
            SqliteRiskStore::open(&db)?.quarantine_workload(
                &agent_id,
                &operator,
                &reason,
                now_unix_ms(),
            )?;
            Ok(serde_json::json!({"agent_id": agent_id, "status": "quarantined"}).to_string())
        }

        Commands::SignalForwarder {
            listen,
            target,
            svid,
            svid_key,
            server_ca,
        } => {
            let token = std::env::var("RISK_GUARD_FORWARDER_TOKEN").map_err(|_| {
                RiskGuardError::InvalidArgument("set RISK_GUARD_FORWARDER_TOKEN".into())
            })?;
            crate::signal_forwarder::serve(
                listen,
                crate::signal_forwarder::ForwarderConfig {
                    target,
                    svid_cert: svid,
                    svid_key,
                    server_ca,
                },
                token.trim(),
            )
            .await?;
            Ok(serde_json::json!({"status": "stopped"}).to_string())
        }

        Commands::FeaturePublisher {
            target,
            svid,
            svid_key,
            server_ca,
            opensearch_url,
            opensearch_user_file,
            opensearch_password_file,
            opensearch_ca,
            opensearch_insecure,
            trust_domain,
            trust_domain_from_svid,
            interval,
            dry_run,
        } => {
            let access = crate::feature_publisher::OpenSearchAccess {
                url: opensearch_url,
                user_file: opensearch_user_file,
                password_file: opensearch_password_file,
                ca_file: opensearch_ca,
                insecure: opensearch_insecure,
            };
            if dry_run {
                return crate::feature_publisher::dry_run(
                    &access,
                    trust_domain.as_deref(),
                    crate::store::now_wall_ms(),
                )
                .await;
            }
            let server_ca = server_ca
                .ok_or_else(|| RiskGuardError::InvalidArgument("--server-ca is required".into()))?;
            if interval < 10 {
                return Err(RiskGuardError::InvalidArgument(
                    "--interval must be at least 10 seconds (Risk Guard accepts one batch per 10 seconds per sender)".into(),
                ));
            }
            crate::feature_publisher::run(
                crate::feature_publisher::PublisherConfig {
                    target,
                    svid_cert: svid,
                    svid_key,
                    server_ca,
                    opensearch: access,
                    trust_domain,
                    trust_domain_from_svid,
                    interval: std::time::Duration::from_secs(interval),
                },
                async {
                    let _ = tokio::signal::ctrl_c().await;
                },
            )
            .await;
            Ok(serde_json::json!({"status": "stopped"}).to_string())
        }

        Commands::TwoPersonEnable { db } => {
            SqliteRiskStore::open(&db)?.require_two_person(now_unix_ms())?;
            Ok(serde_json::json!({"two_person_required": true}).to_string())
        }

        Commands::ChangePropose {
            db,
            kind,
            agent_id,
            scope,
            context_id,
            proposer,
            reason,
        } => {
            let params = serde_json::json!({"scope": scope, "context_id": context_id});
            let id = SqliteRiskStore::open(&db)?.propose_change(
                &kind,
                &agent_id,
                &params,
                &reason,
                &proposer,
                now_unix_ms(),
            )?;
            Ok(serde_json::json!({"id": id, "status": "pending", "needs": "approval by someone other than the proposer"}).to_string())
        }

        Commands::ChangeDecide {
            db,
            id,
            decider,
            approve,
            reject: _,
            reason,
        } => {
            let decision = SqliteRiskStore::open(&db)?.decide_change(
                &id,
                &decider,
                approve,
                &reason,
                now_unix_ms(),
            )?;
            Ok(serde_json::to_string_pretty(&decision)?)
        }

        Commands::ChangeList { db, limit } => Ok(serde_json::to_string_pretty(
            &SqliteRiskStore::open(&db)?.list_changes(limit, now_unix_ms())?,
        )?),

        Commands::WorkloadRelease {
            db,
            agent_id,
            operator,
            reason,
            break_glass,
        } => {
            let store = SqliteRiskStore::open(&db)?;
            let was = if break_glass {
                store.release_workload_break_glass(&agent_id, &operator, &reason, now_unix_ms())?
            } else {
                store.release_workload(&agent_id, &operator, &reason, now_unix_ms())?
            };
            Ok(serde_json::json!({"agent_id": agent_id, "status": if was { "released" } else { "was not quarantined" }}).to_string())
        }

        Commands::ReplayExport {
            db,
            agent_id,
            context_id,
            out,
        } => {
            let bundle = SqliteRiskStore::open(&db)?
                .export_replay_bundle(&agent_id, context_id.as_deref())?;
            std::fs::write(&out, serde_json::to_vec_pretty(&bundle)?).map_err(|error| {
                RiskGuardError::Internal(format!("cannot write the bundle: {error}"))
            })?;
            Ok(serde_json::json!({
                "bundle": out.display().to_string(), "events": bundle.events.len(), "history_complete": bundle.history.complete,
                "problems": bundle.history.problems, "content_hash": bundle.content_hash,
            })
            .to_string())
        }

        Commands::Backup { db, out } => {
            let report = crate::backup::backup(&db, &out)?;
            Ok(serde_json::to_string_pretty(&report)?)
        }

        Commands::BackupVerify { file } => {
            let report = crate::backup::verify(&file)?;
            Ok(serde_json::to_string_pretty(&report)?)
        }

        Commands::Restore { from, db, force } => {
            let report = crate::backup::restore(&from, &db, force)?;
            Ok(serde_json::to_string_pretty(&report)?)
        }

        Commands::ReplayVerify {
            bundle,
            allow_incomplete,
        } => {
            let bundle: crate::replay::ReplayBundle =
                serde_json::from_slice(&std::fs::read(&bundle).map_err(|error| {
                    RiskGuardError::Internal(format!("cannot read the bundle: {error}"))
                })?)?;
            let report = crate::replay::replay(&bundle, allow_incomplete)?;
            let text = serde_json::to_string_pretty(&report)?;
            if report.reproduced {
                Ok(text)
            } else {
                Err(RiskGuardError::Internal(format!(
                    "replay did not reproduce the recorded decisions:
{text}"
                )))
            }
        }

        Commands::SupervisorSilenceList { db, limit } => Ok(serde_json::to_string_pretty(
            &SqliteRiskStore::open(&db)?.list_supervisor_silence(limit)?,
        )?),

        Commands::WorkloadQuarantineList { db } => Ok(serde_json::to_string_pretty(
            &SqliteRiskStore::open(&db)?.list_quarantined()?,
        )?),

        Commands::RestrictionClear {
            db,
            agent_id,
            sandbox_id,
            context_id,
            scope,
            operator,
            reason,
            break_glass,
        } => {
            let target = restriction_target(
                agent_id.as_deref(),
                sandbox_id.as_deref(),
                context_id.as_deref(),
            )?;
            let store = SqliteRiskStore::open(&db)?;
            let cleared = if break_glass {
                store.clear_restriction_break_glass(
                    target,
                    &scope,
                    &operator,
                    &reason,
                    now_unix_ms(),
                )?
            } else {
                store.clear_restriction(target, &scope, &operator, &reason, now_unix_ms())?
            };
            Ok(serde_json::to_string_pretty(&cleared)?)
        }

        Commands::Dashboard {
            listen,
            db,
            operator_token_file,
            entra_tenant_id,
            entra_client_id,
            entra_admin_oids,
            entra_viewer_oids,
            entra_require_sign_in_to_read,
        } => {
            let entra = match (entra_tenant_id, entra_client_id) {
                (Some(tenant), Some(client)) => Some(crate::entra_auth::EntraConfig::new(
                    &tenant,
                    &client,
                    &entra_admin_oids,
                    &entra_viewer_oids,
                )?),
                _ => None,
            };
            crate::operator_dashboard::serve_with_sign_in(
                listen,
                db,
                operator_token_file,
                entra,
                entra_require_sign_in_to_read,
            )
            .await?;
            Ok(serde_json::json!({"status": "stopped", "listen": listen.to_string()}).to_string())
        }
        Commands::DemoDashboard { listen, db } => {
            crate::dashboard::serve_live_dashboard(listen, db).await?;
            Ok(serde_json::json!({"status": "stopped", "listen": listen.to_string()}).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{PROFILE_COLD_START_NEW, PROFILE_MAINTENANCE_CLEANUP};
    use crate::types::{HardeningCandidate, RawRequestInput, RiskEvaluation};
    use tempfile::TempDir;

    const SAMPLE_POLICY_YAML: &str = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: openshell-risk-guard
    on_error: fail_closed
network_policies:
  _provider_github:
    endpoints:
      - host: uploads.github.com
        port: 443
    binaries:
      - path: /usr/bin/gh
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        credential_binding:
          provider: github-token
        deny_rules:
          - method: DELETE
            path: /repos/**
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/gh
      - path: /usr/bin/git
"#;

    #[tokio::test]
    async fn epoch_create_uses_provisioned_baselines_and_extracts_credentialed_endpoints() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let db_path = temp_dir.path().join("risk-guard.db");
        open_and_seed_store(&db_path).expect("explicitly seed test fixtures");
        let policy_path = temp_dir.path().join("policy.yaml");
        std::fs::write(&policy_path, SAMPLE_POLICY_YAML).expect("write policy file");

        let cli = Cli::try_parse_from([
            "openshell-risk-guard",
            "epoch-create",
            "--db",
            db_path.to_str().unwrap(),
            "--sandbox-id",
            "sbx-cli-test-1",
            "--epoch-id",
            "ep-cli-test-1",
            "--task-profile",
            "repo-triage-readonly",
            "--mode",
            "enforce",
            "--policy",
            policy_path.to_str().unwrap(),
        ])
        .expect("parse epoch-create CLI");

        let output = execute_cli(cli).await.expect("execute epoch-create");
        let created_epoch: EpochRecord =
            serde_json::from_str(&output).expect("parse EpochRecord JSON");

        assert_eq!(created_epoch.sandbox_id, "sbx-cli-test-1");
        assert_eq!(created_epoch.epoch_id, "ep-cli-test-1");
        assert_eq!(created_epoch.task_profile, PROFILE_REPO_TRIAGE_READONLY);
        assert_eq!(created_epoch.mode, EnforcementMode::Enforce);
        assert!(created_epoch.active);
        assert!(created_epoch.active_policy_hash.is_some());
        assert!(
            created_epoch
                .credentialed_endpoints
                .contains(&("api.github.com".to_string(), 443))
        );
        assert!(
            created_epoch
                .credentialed_endpoints
                .contains(&("uploads.github.com".to_string(), 443))
        );

        let store = SqliteRiskStore::open(&db_path).expect("reopen sqlite store");
        assert!(
            store
                .get_baseline(PROFILE_REPO_TRIAGE_READONLY)
                .expect("get repo-triage-readonly baseline")
                .is_some()
        );
        assert!(
            store
                .get_baseline(PROFILE_MAINTENANCE_CLEANUP)
                .expect("get maintenance-cleanup baseline")
                .is_some()
        );
        assert!(
            store
                .get_baseline(PROFILE_COLD_START_NEW)
                .expect("get cold-start-new baseline")
                .is_some()
        );

        let stored_epoch = store
            .get_active_epoch("sbx-cli-test-1")
            .expect("query active epoch")
            .expect("active epoch should exist");
        assert_eq!(stored_epoch, created_epoch);

        let snapshot = store
            .latest_policy_snapshot("sbx-cli-test-1")
            .expect("query policy snapshot")
            .expect("policy snapshot should exist");
        assert_eq!(Some(snapshot.0), created_epoch.active_policy_hash);
    }

    #[tokio::test]
    async fn decision_inspect_returns_recorded_evaluations_as_json() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let db_path = temp_dir.path().join("risk-guard.db");
        open_and_seed_store(&db_path).expect("explicitly seed test fixtures");
        let policy_path = temp_dir.path().join("policy.yaml");
        std::fs::write(&policy_path, SAMPLE_POLICY_YAML).expect("write policy file");

        execute_cli(Cli {
            command: Commands::EpochCreate {
                db: db_path.clone(),
                sandbox_id: "sbx-inspect-1".to_string(),
                gateway_id: "local-gateway".to_string(),
                epoch_id: Some("ep-inspect-1".to_string()),
                task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
                mode: "enforce".to_string(),
                policy: Some(policy_path),
            },
        })
        .await
        .expect("create epoch");

        let store = SqliteRiskStore::open(&db_path).expect("open store");
        let normalizer = CanonicalNormalizer::new_default(crate::sidecar::INSECURE_TEST_HMAC_KEY);
        let detector = InteractionRiskDetector::new_default();

        let benign_req = normalizer
            .normalize(&RawRequestInput {
                request_id: "req-inspect-allow-1".to_string(),
                sandbox_id: "sbx-inspect-1".to_string(),
                sandbox_name: "sbx-inspect-1".to_string(),
                workspace: "/work".to_string(),
                scheme: "https".to_string(),
                host: "api.github.com".to_string(),
                port: 443,
                method: "GET".to_string(),
                path: "/repos/org/docs-site".to_string(),
                binary_path: Some("/usr/bin/gh".to_string()),
                pid: Some(1234),
                ancestors: vec![],
                timestamp_ms: 1_760_000_001_000,
            })
            .expect("normalize benign request");
        store
            .evaluate_and_commit_atomic(&benign_req, &detector)
            .expect("evaluate benign request");

        let misuse_req = normalizer
            .normalize(&RawRequestInput {
                request_id: "req-inspect-deny-1".to_string(),
                sandbox_id: "sbx-inspect-1".to_string(),
                sandbox_name: "sbx-inspect-1".to_string(),
                workspace: "/work".to_string(),
                scheme: "https".to_string(),
                host: "api.github.com".to_string(),
                port: 443,
                method: "DELETE".to_string(),
                path: "/repos/org/other-repo".to_string(),
                binary_path: Some("/usr/bin/gh".to_string()),
                pid: Some(1235),
                ancestors: vec![],
                timestamp_ms: 1_760_000_002_000,
            })
            .expect("normalize misuse request");
        store
            .evaluate_and_commit_atomic(&misuse_req, &detector)
            .expect("evaluate misuse request");

        let inspect_cli = Cli::try_parse_from([
            "openshell-risk-guard",
            "decision-inspect",
            "--db",
            db_path.to_str().unwrap(),
            "--sandbox-id",
            "sbx-inspect-1",
            "--limit",
            "10",
        ])
        .expect("parse decision-inspect CLI");

        let output = execute_cli(inspect_cli)
            .await
            .expect("execute decision-inspect");
        let decisions: Vec<RiskEvaluation> =
            serde_json::from_str(&output).expect("parse Vec<RiskEvaluation>");

        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].request_id, "req-inspect-allow-1");
        assert_eq!(decisions[0].outcome, DecisionOutcome::Allow);
        assert_eq!(decisions[1].request_id, "req-inspect-deny-1");
        assert_eq!(decisions[1].outcome, DecisionOutcome::Deny);
    }

    #[tokio::test]
    async fn hardening_report_generates_prover_verified_candidate_and_writes_out_file() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let db_path = temp_dir.path().join("risk-guard.db");
        open_and_seed_store(&db_path).expect("explicitly seed test fixtures");
        let policy_path = temp_dir.path().join("policy.yaml");
        let report_path = temp_dir.path().join("reports").join("hardening.json");
        std::fs::write(&policy_path, SAMPLE_POLICY_YAML).expect("write policy file");

        execute_cli(Cli {
            command: Commands::EpochCreate {
                db: db_path.clone(),
                sandbox_id: "sbx-harden-1".to_string(),
                gateway_id: "local-gateway".to_string(),
                epoch_id: Some("ep-harden-1".to_string()),
                task_profile: PROFILE_REPO_TRIAGE_READONLY.to_string(),
                mode: "enforce".to_string(),
                policy: Some(policy_path.clone()),
            },
        })
        .await
        .expect("create epoch");

        let store = SqliteRiskStore::open(&db_path).expect("open store");
        let normalizer = CanonicalNormalizer::new_default(crate::sidecar::INSECURE_TEST_HMAC_KEY);
        let detector = InteractionRiskDetector::new_default();

        for (idx, path) in ["/repos/org/docs-site", "/repos/org/docs-site/issues"]
            .into_iter()
            .enumerate()
        {
            let req = normalizer
                .normalize(&RawRequestInput {
                    request_id: format!("req-harden-{}", idx + 1),
                    sandbox_id: "sbx-harden-1".to_string(),
                    sandbox_name: "sbx-harden-1".to_string(),
                    workspace: "/work".to_string(),
                    scheme: "https".to_string(),
                    host: "api.github.com".to_string(),
                    port: 443,
                    method: "GET".to_string(),
                    path: path.to_string(),
                    binary_path: Some("/usr/bin/gh".to_string()),
                    pid: Some(2000 + idx as u32),
                    ancestors: vec![],
                    timestamp_ms: 1_760_000_010_000 + (idx as i64) * 1_000,
                })
                .expect("normalize request");
            store
                .evaluate_and_commit_atomic(&req, &detector)
                .expect("record decision");
        }

        let report_cli = Cli::try_parse_from([
            "openshell-risk-guard",
            "hardening-report",
            "--db",
            db_path.to_str().unwrap(),
            "--sandbox-id",
            "sbx-harden-1",
            "--policy",
            policy_path.to_str().unwrap(),
            "--out",
            report_path.to_str().unwrap(),
        ])
        .expect("parse hardening-report CLI");

        let output = execute_cli(report_cli)
            .await
            .expect("execute hardening-report");
        let candidate: HardeningCandidate =
            serde_json::from_str(&output).expect("parse HardeningCandidate JSON");

        assert_eq!(candidate.sandbox_id, "sbx-harden-1");
        assert_eq!(candidate.epoch_id, "ep-harden-1");
        assert_eq!(candidate.observed_requests, 2);
        assert!(candidate.completeness_ok);
        assert!(candidate.two_step_proof.step1_middleware_invariant);
        assert_eq!(
            candidate.two_step_proof.step2_prover_verdict,
            "within_boundary"
        );
        assert!(candidate.two_step_proof.verified_non_expanding);
        assert_eq!(candidate.replay_total_requests, 2);
        assert_eq!(candidate.replay_would_block, 0);
        assert_eq!(candidate.status, "ready");
        assert!(!candidate.diff_summary.is_empty());

        let disk_contents =
            std::fs::read_to_string(&report_path).expect("read written report file");
        let disk_candidate: HardeningCandidate =
            serde_json::from_str(&disk_contents).expect("parse written HardeningCandidate JSON");
        assert_eq!(disk_candidate, candidate);

        let saved = store
            .list_recommendations("sbx-harden-1")
            .expect("list saved recommendations");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0], candidate);
    }

    #[tokio::test]
    async fn serve_hosts_both_middleware_and_interceptor_services() {
        use openshell_core::extension_protocol::{ExtensionFamily, gateway_metadata};
        use openshell_core::proto::MiddlewareDescribeRequest;
        use openshell_core::proto::gateway_interceptor::v1::{
            DescribeRequest, gateway_interceptor_client::GatewayInterceptorClient,
        };
        use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
        use std::time::Duration;

        let temp_dir = TempDir::new().expect("create temp dir");
        let db_path = temp_dir.path().join("risk-guard.db");

        open_and_seed_store(&db_path).expect("explicitly seed test fixtures");
        let probe_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let listen_addr = probe_listener.local_addr().expect("get local addr");
        drop(probe_listener);

        let serve_cli = Cli::try_parse_from([
            "openshell-risk-guard",
            "serve",
            "--listen",
            &listen_addr.to_string(),
            "--db",
            db_path.to_str().unwrap(),
            "--gateway-id",
            "gw-cli-test",
            "--audience",
            "urn:openshell:extension:risk-guard",
            "--allow-insecure-local-test",
            "--default-task-profile",
            "repo-triage-readonly",
        ])
        .expect("parse serve CLI");

        let server_handle = tokio::spawn(async move { execute_cli(serve_cli).await });

        let endpoint = format!("http://{listen_addr}");
        let mut mw_client = None;
        for _ in 0..40 {
            if let Ok(client) = SupervisorMiddlewareClient::connect(endpoint.clone()).await {
                mw_client = Some(client);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let mut mw_client = mw_client.expect("connect SupervisorMiddlewareClient");
        let mw_manifest = mw_client
            .describe(MiddlewareDescribeRequest {
                gateway: Some(gateway_metadata(ExtensionFamily::SupervisorMiddleware)),
            })
            .await
            .expect("describe middleware")
            .into_inner();
        assert_eq!(mw_manifest.name, "openshell/behavioral-risk-guard");

        let mut ic_client = GatewayInterceptorClient::connect(endpoint)
            .await
            .expect("connect GatewayInterceptorClient");
        let ic_manifest = ic_client
            .describe(DescribeRequest {
                gateway: Some(gateway_metadata(ExtensionFamily::GatewayInterceptor)),
            })
            .await
            .expect("describe interceptor")
            .into_inner();
        assert_eq!(ic_manifest.name, "risk-guard-governance");

        server_handle.abort();
    }
}
