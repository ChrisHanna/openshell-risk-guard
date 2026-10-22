// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! `GatewayInterceptor` gRPC service (Wave 2 - `t07-interceptor-grpc`).

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, validate_gateway_metadata,
};
use openshell_core::proto::gateway_interceptor::v1::{
    DescribeRequest, GatewayInterceptorPhase, InterceptorBinding, InterceptorEvaluation,
    InterceptorManifest, InterceptorResult, InterceptorSelector, ProviderProfileSnapshot,
    ProviderProfileSnapshotRequest,
    gateway_interceptor_server::{GatewayInterceptor, GatewayInterceptorServer},
    interceptor_evaluation,
};
use prost_types::{ListValue, Struct, Value as ProtoValue, value::Kind};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

use crate::error::RiskGuardError;
use crate::types::{
    AuthVerifier, BindingAudit, EnforcementMode, EpochRecord, HardeningEngine, RiskStore,
    SandboxBinding,
};
use crate::workload_identity::derive_workload;

const INTERCEPTOR_MANIFEST_NAME: &str = "risk-guard-governance";
const EXTENSION_IMPLEMENTATION_NAME: &str = "openshell/risk-guard-governance";
const OPENSHELL_SERVICE: &str = "openshell.v1.OpenShell";
const DEFAULT_REQUIRED_MIDDLEWARE_NAME: &str = "risk-guard";
const POLICY_YAML_ANNOTATION: &str = "openshell.nvidia.com/policy-yaml";
const POLICY_HASH_ANNOTATION: &str = "openshell.nvidia.com/policy-hash";
const AGENT_ID_ANNOTATION: &str = "openshell.nvidia.com/agent-id";
const AGENT_REVISION_ANNOTATION: &str = "openshell.nvidia.com/agent-revision";
const RUN_ID_ANNOTATION: &str = "openshell.nvidia.com/run-id";
/// A readable name shown next to a labeled workload ID, for example an Entra application's display name.
const AGENT_NAME_ANNOTATION: &str = "openshell.nvidia.com/agent-name";

/// Who may attach a sandbox to a workload ID when it is created, and whether
/// a workload ID that nobody registered may be created on the fly.
///
/// A workload ID decides which restrictions, baseline and learning history a sandbox
/// inherits, so choosing one is an operator decision. Both settings are off by default:
/// with no allowlist, `openshell.nvidia.com/agent-id` is never honored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentBindingPolicy {
    allowed_principals: BTreeSet<String>,
    auto_register_agents: bool,
    /// Derive the workload from the authenticated `(workspace, principal)` when a sandbox
    /// carries no explicit workload label.
    derive_from_principal: bool,
    /// Let OpenShell's unauthenticated local-development user own a workload and pass the
    /// label allowlist. For local testing only: that caller proves nothing about who it is.
    allow_local_dev_principal: bool,
}

impl AgentBindingPolicy {
    /// Entries are exact `operator:<subject>` or `user:<subject>` values as OpenShell
    /// reports the authenticated caller. Sandbox, peer and anonymous callers can never be
    /// allowlisted, and wildcards are rejected.
    pub fn new<I, S>(
        allowed_principals: I,
        auto_register_agents: bool,
    ) -> std::result::Result<Self, RiskGuardError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowed = BTreeSet::new();
        for entry in allowed_principals {
            let entry = entry.as_ref().trim();
            let valid = entry.split_once(':').is_some_and(|(kind, subject)| {
                matches!(kind, "operator" | "user")
                    && !subject.is_empty()
                    && !subject.contains('*')
                    && !subject.chars().any(|c| c.is_control() || c.is_whitespace())
            });
            if !valid {
                return Err(RiskGuardError::InvalidArgument(format!(
                    "workload binding principal '{entry}' must be exactly 'operator:<subject>' or 'user:<subject>' with no wildcard"
                )));
            }
            allowed.insert(entry.to_string());
        }
        if auto_register_agents && allowed.is_empty() {
            return Err(RiskGuardError::InvalidArgument(
                "auto-registering agents requires at least one allowlisted binding principal"
                    .into(),
            ));
        }
        Ok(Self {
            allowed_principals: allowed,
            auto_register_agents,
            derive_from_principal: false,
            allow_local_dev_principal: false,
        })
    }

    /// Bind sandboxes that carry no workload label to a workload derived from the
    /// authenticated `(workspace, principal)` that created them. Nothing in the request can
    /// choose or forge that workload, so no allowlist is needed.
    #[must_use]
    pub fn with_principal_derivation(mut self, enabled: bool) -> Self {
        self.derive_from_principal = enabled;
        self
    }

    /// Allow OpenShell's unauthenticated local-development user to bind. Off by default.
    #[must_use]
    pub fn with_local_dev_principals(mut self, enabled: bool) -> Self {
        self.allow_local_dev_principal = enabled;
        self
    }

    /// Whether any principal may bind at all.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.allowed_principals.is_empty() || self.derive_from_principal
    }

    /// Whether unlabeled sandboxes are bound to a principal-derived workload.
    #[must_use]
    pub fn derives_from_principal(&self) -> bool {
        self.derive_from_principal
    }

    /// Whether the authenticated caller summary from OpenShell is allowlisted.
    #[must_use]
    pub fn permits(&self, principal: &HashMap<String, String>) -> bool {
        if principal.get("provider").map(String::as_str) == Some("local_dev")
            && !self.allow_local_dev_principal
        {
            return false;
        }
        match (
            principal.get("kind").map(String::as_str),
            principal.get("subject").map(|subject| subject.trim()),
        ) {
            (Some(kind @ ("operator" | "user")), Some(subject)) if !subject.is_empty() => self
                .allowed_principals
                .contains(&format!("{kind}:{subject}")),
            _ => false,
        }
    }
}
const CONTAINMENT_PROOF_TIMEOUT: Duration = Duration::from_secs(5);

/// Control-plane `GatewayInterceptor` gRPC service enforcing monotonic policy
/// hardening, fail-closed `risk-guard` middleware preservation, and automatic
/// sandbox epoch/snapshot registration.
#[derive(Clone)]
pub struct RiskGuardInterceptorService {
    pub auth: Arc<dyn AuthVerifier>,
    pub store: Arc<dyn RiskStore>,
    pub hardening: Arc<dyn HardeningEngine>,
    pub gateway_id: String,
    pub expected_audience: String,
    pub default_task_profile: String,
    pub required_middleware_name: String,
    pub agent_binding: AgentBindingPolicy,
}

impl fmt::Debug for RiskGuardInterceptorService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RiskGuardInterceptorService")
            .field("gateway_id", &self.gateway_id)
            .field("expected_audience", &self.expected_audience)
            .field("default_task_profile", &self.default_task_profile)
            .field("required_middleware_name", &self.required_middleware_name)
            .field("agent_binding_enabled", &self.agent_binding.is_enabled())
            .finish_non_exhaustive()
    }
}

impl RiskGuardInterceptorService {
    #[must_use]
    pub fn new(
        auth: Arc<dyn AuthVerifier>,
        store: Arc<dyn RiskStore>,
        hardening: Arc<dyn HardeningEngine>,
        gateway_id: impl Into<String>,
        expected_audience: impl Into<String>,
        default_task_profile: impl Into<String>,
    ) -> Self {
        Self {
            auth,
            store,
            hardening,
            gateway_id: gateway_id.into(),
            expected_audience: expected_audience.into(),
            default_task_profile: default_task_profile.into(),
            required_middleware_name: DEFAULT_REQUIRED_MIDDLEWARE_NAME.to_string(),
            agent_binding: AgentBindingPolicy::default(),
        }
    }

    /// Allow allowlisted principals to attach sandboxes to workload IDs at creation.
    #[must_use]
    pub fn with_agent_binding(mut self, policy: AgentBindingPolicy) -> Self {
        self.agent_binding = policy;
        self
    }

    #[must_use]
    pub fn with_required_middleware_name(mut self, name: impl Into<String>) -> Self {
        self.required_middleware_name = name.into();
        self
    }

    #[must_use]
    pub fn into_server(self) -> GatewayInterceptorServer<Self> {
        GatewayInterceptorServer::new(self)
    }

    #[must_use]
    pub fn manifest(&self) -> InterceptorManifest {
        InterceptorManifest {
            name: INTERCEPTOR_MANIFEST_NAME.to_string(),
            failure_policy: "fail_closed".to_string(),
            provider_profiles: false,
            expected_audience: self.expected_audience.clone(),
            extension: Some(extension_metadata(
                ExtensionFamily::GatewayInterceptor,
                EXTENSION_IMPLEMENTATION_NAME,
                openshell_core::VERSION,
                [],
            )),
            bindings: vec![
                validate_binding("validate-create-sandbox", "CreateSandbox"),
                post_commit_binding("post-commit-create-sandbox", "CreateSandbox"),
                validate_binding("validate-update-config", "UpdateConfig"),
                post_commit_binding("post-commit-update-config", "UpdateConfig"),
                validate_binding("validate-approve-draft-chunk", "ApproveDraftChunk"),
                post_commit_binding("post-commit-approve-draft-chunk", "ApproveDraftChunk"),
                validate_binding("validate-approve-all-draft-chunks", "ApproveAllDraftChunks"),
                post_commit_binding(
                    "post-commit-approve-all-draft-chunks",
                    "ApproveAllDraftChunks",
                ),
                validate_binding("validate-submit-policy-analysis", "SubmitPolicyAnalysis"),
                post_commit_binding("post-commit-submit-policy-analysis", "SubmitPolicyAnalysis"),
                post_commit_binding("post-commit-delete-sandbox", "DeleteSandbox"),
            ],
        }
    }

    fn evaluate_validate(
        &self,
        method: &str,
        operation: &Value,
        current_state: Option<&Value>,
        principal: &HashMap<String, String>,
    ) -> std::result::Result<InterceptorResult, Status> {
        match method {
            "UpdateConfig" => self.validate_update_config(operation, current_state),
            "CreateSandbox" => Ok(self.validate_create_sandbox(operation, principal)),
            "ApproveAllDraftChunks" => {
                self.validate_approve_all_draft_chunks(operation, current_state, principal)
            }
            "ApproveDraftChunk" => {
                self.validate_approve_draft_chunk(operation, current_state, principal)
            }
            "SubmitPolicyAnalysis" => {
                self.validate_submit_policy_analysis(operation, current_state, principal)
            }
            _ => Ok(allow()),
        }
    }

    fn validate_update_config(
        &self,
        operation: &Value,
        current_state: Option<&Value>,
    ) -> std::result::Result<InterceptorResult, Status> {
        if requests_auto_proposal_approval(operation) {
            return Ok(deny(
                "risk-guard forbids proposal_approval_mode=auto on governed sandboxes",
            ));
        }

        let policy_yaml = extract_policy_yaml(operation);
        let policy_obj = extract_policy_object(operation);

        if policy_yaml.is_some() || policy_obj.is_some() {
            let has_middleware = self.check_required_middleware(policy_yaml.as_deref(), policy_obj);
            if !has_middleware {
                return Ok(deny(
                    "governed sandbox policy must retain fail_closed risk-guard middleware binding",
                ));
            }
        }

        let candidate_yaml = match policy_yaml {
            Some(yaml) => Some(yaml),
            None => policy_obj.map(policy_object_to_yaml).transpose()?,
        };
        if let Some(candidate_yaml) = candidate_yaml {
            let sandbox_candidates = extract_sandbox_candidates(operation, current_state, None);
            for sandbox_id in sandbox_candidates {
                if let Some((_current_hash, current_yaml)) = self
                    .store
                    .latest_policy_snapshot(&sandbox_id)
                    .map_err(risk_guard_error_to_status)?
                {
                    let proof = match self.hardening.verify_two_step_containment(
                        &current_yaml,
                        &candidate_yaml,
                        CONTAINMENT_PROOF_TIMEOUT,
                    ) {
                        Ok(proof) => proof,
                        Err(err) => {
                            return Ok(deny(&format!(
                                "control-plane monotonicity violation: candidate policy expands permissions beyond current epoch boundary ({err})"
                            )));
                        }
                    };

                    if !proof.verified_non_expanding {
                        return Ok(deny(&format!(
                            "control-plane monotonicity violation: candidate policy expands permissions beyond current epoch boundary ({:?})",
                            proof.step2_counterexample_or_reason
                        )));
                    }

                    let mut result = allow();
                    result
                        .log_annotations
                        .insert("sandbox_id".to_string(), sandbox_id);
                    result
                        .log_annotations
                        .insert("two_step_verdict".to_string(), proof.step2_prover_verdict);
                    return Ok(result);
                }
            }
        }

        Ok(allow())
    }

    fn validate_create_sandbox(
        &self,
        operation: &Value,
        principal: &HashMap<String, String>,
    ) -> InterceptorResult {
        // Early, friendlier refusal. POST_COMMIT re-checks the principal, so a
        // difference between request and response shapes cannot become a bypass.
        if binding_annotations_present(operation) && !self.agent_binding.permits(principal) {
            return deny(
                "risk-guard: only an allowlisted operator or user principal may attach a sandbox to a workload ID (openshell.nvidia.com/agent-id)",
            );
        }
        let policy_yaml = extract_policy_yaml(operation);
        let policy_obj = extract_policy_object(operation);

        if policy_yaml.is_some() || policy_obj.is_some() {
            let has_middleware = self.check_required_middleware(policy_yaml.as_deref(), policy_obj);
            if !has_middleware {
                return deny(
                    "governed sandbox policy must retain fail_closed risk-guard middleware binding",
                );
            }
        }

        allow()
    }

    fn validate_approve_all_draft_chunks(
        &self,
        operation: &Value,
        current_state: Option<&Value>,
        principal: &HashMap<String, String>,
    ) -> std::result::Result<InterceptorResult, Status> {
        if let Some(epoch) =
            self.find_active_governed_epoch(operation, current_state, Some(principal))?
        {
            return Ok(deny(&format!(
                "risk-guard forbids ApproveAllDraftChunks while sandbox '{}' is in active governed epoch '{}'",
                epoch.sandbox_id, epoch.epoch_id
            )));
        }
        Ok(allow())
    }

    fn validate_approve_draft_chunk(
        &self,
        operation: &Value,
        current_state: Option<&Value>,
        principal: &HashMap<String, String>,
    ) -> std::result::Result<InterceptorResult, Status> {
        let Some(epoch) =
            self.find_active_governed_epoch(operation, current_state, Some(principal))?
        else {
            return Ok(allow());
        };

        let candidate_yaml = extract_authored_policy_yaml(operation)?;

        if let Some(candidate_yaml) = candidate_yaml
            && let Some((_hash, current_yaml)) = self
                .store
                .latest_policy_snapshot(&epoch.sandbox_id)
                .map_err(risk_guard_error_to_status)?
            && let Ok(proof) = self.hardening.verify_two_step_containment(
                &current_yaml,
                &candidate_yaml,
                CONTAINMENT_PROOF_TIMEOUT,
            )
            && proof.verified_non_expanding
        {
            return Ok(allow());
        }

        Ok(deny(&format!(
            "risk-guard forbids unverified draft chunk rule expansion while sandbox '{}' is in active governed epoch '{}'",
            epoch.sandbox_id, epoch.epoch_id
        )))
    }

    fn validate_submit_policy_analysis(
        &self,
        operation: &Value,
        current_state: Option<&Value>,
        principal: &HashMap<String, String>,
    ) -> std::result::Result<InterceptorResult, Status> {
        let Some(epoch) =
            self.find_active_governed_epoch(operation, current_state, Some(principal))?
        else {
            return Ok(allow());
        };

        let proposed_chunks = operation
            .get("proposed_chunks")
            .or_else(|| operation.get("proposedChunks"));

        let is_summary_only = matches!(proposed_chunks, Some(Value::Array(chunks)) if chunks.is_empty())
            && operation.get("summaries").is_some();

        if is_summary_only {
            return Ok(allow());
        }

        Ok(deny(&format!(
            "risk-guard forbids unverified policy expansion proposals while sandbox '{}' is in active governed epoch '{}'",
            epoch.sandbox_id, epoch.epoch_id
        )))
    }

    fn evaluate_post_commit(
        &self,
        method: &str,
        committed_response: &Value,
        principal: &HashMap<String, String>,
    ) -> std::result::Result<InterceptorResult, Status> {
        match method {
            "CreateSandbox" | "UpdateConfig" => {
                self.post_commit_sandbox_mutation(method, committed_response, principal)
            }
            "DeleteSandbox" | "StopSandbox" | "TerminateSandbox" => {
                self.post_commit_sandbox_lifecycle_close(committed_response)
            }
            _ => Ok(allow()),
        }
    }

    fn post_commit_sandbox_lifecycle_close(
        &self,
        committed_response: &Value,
    ) -> std::result::Result<InterceptorResult, Status> {
        let Some(sandbox_id) = extract_post_commit_sandbox_id(committed_response) else {
            return Ok(allow());
        };
        let ended_run_id = self
            .store
            .close_sandbox_lifecycle(&sandbox_id)
            .map_err(risk_guard_error_to_status)?;
        let mut result = allow();
        result
            .log_annotations
            .insert("sandbox_id".to_string(), sandbox_id);
        if let Some(run_id) = ended_run_id {
            result
                .log_annotations
                .insert("ended_run_id".to_string(), run_id);
        }
        Ok(result)
    }

    fn post_commit_sandbox_mutation(
        &self,
        method: &str,
        committed_response: &Value,
        principal: &HashMap<String, String>,
    ) -> std::result::Result<InterceptorResult, Status> {
        let Some(sandbox_id) = extract_post_commit_sandbox_id(committed_response) else {
            return Ok(allow());
        };

        let now_ms = now_unix_ms();
        let policy_yaml = extract_authored_policy_yaml(committed_response)?;
        let explicit_policy_hash = extract_policy_hash(committed_response);

        let mut credentialed_endpoints = BTreeSet::new();
        let mut active_policy_hash = explicit_policy_hash.clone();

        if let Some(ref yaml) = policy_yaml {
            credentialed_endpoints = self
                .hardening
                .extract_credentialed_endpoints(yaml)
                .map_err(risk_guard_error_to_status)?;
            if active_policy_hash.is_none() {
                active_policy_hash = Some(sha256_hex(yaml.as_bytes()));
            }
        }

        let mut result = allow();
        result
            .log_annotations
            .insert("sandbox_id".to_string(), sandbox_id.clone());

        if method == "CreateSandbox" {
            let existing_epoch = self
                .store
                .get_active_epoch(&sandbox_id)
                .map_err(risk_guard_error_to_status)?;
            if existing_epoch.is_none() {
                let (policy_profile, policy_mode) = match policy_yaml.as_deref() {
                    Some(yaml) => policy_scoring_context(yaml, &self.required_middleware_name)?,
                    None => (None, EnforcementMode::Enforce),
                };
                let task_profile = extract_task_profile(committed_response)
                    .or(policy_profile)
                    .unwrap_or_else(|| self.default_task_profile.clone());
                let baseline = self
                    .store
                    .get_baseline(&task_profile)
                    .map_err(risk_guard_error_to_status)?
                    .ok_or_else(|| {
                        Status::failed_precondition(format!(
                            "baseline '{task_profile}' is not provisioned; use baseline-import"
                        ))
                    })?;
                let baseline_hash = crate::detector::compute_baseline_hash(&baseline);

                let epoch_id = format!("ep_{sandbox_id}_1");
                let epoch = EpochRecord {
                    epoch_id: epoch_id.clone(),
                    gateway_id: self.gateway_id.clone(),
                    sandbox_id: sandbox_id.clone(),
                    task_profile: baseline.task_profile.clone(),
                    baseline_hash,
                    mode: policy_mode,
                    active: true,
                    next_sequence: 1,
                    created_at_ms: now_ms,
                    credentialed_endpoints: credentialed_endpoints.clone(),
                    active_policy_hash: active_policy_hash.clone(),
                };
                self.store
                    .upsert_epoch(&epoch)
                    .map_err(risk_guard_error_to_status)?;
                result
                    .log_annotations
                    .insert("epoch_id".to_string(), epoch_id);
            } else if let Some(epoch) = existing_epoch {
                result
                    .log_annotations
                    .insert("epoch_id".to_string(), epoch.epoch_id);
            }
        }

        if let Some(ref yaml) = policy_yaml {
            let policy_hash = active_policy_hash
                .clone()
                .unwrap_or_else(|| sha256_hex(yaml.as_bytes()));
            let source = if method == "CreateSandbox" {
                "create_sandbox"
            } else {
                "update_config"
            };
            self.store
                .record_policy_snapshot(
                    &sandbox_id,
                    &policy_hash,
                    yaml,
                    &credentialed_endpoints,
                    source,
                    now_ms,
                )
                .map_err(risk_guard_error_to_status)?;
            result
                .log_annotations
                .insert("policy_hash".to_string(), policy_hash);
            result.log_annotations.insert(
                "credentialed_endpoints_count".to_string(),
                credentialed_endpoints.len().to_string(),
            );
        } else if let Some(policy_hash) = active_policy_hash {
            result
                .log_annotations
                .insert("policy_hash".to_string(), policy_hash);
        }

        if method == "CreateSandbox" {
            self.bind_created_sandbox(&sandbox_id, committed_response, principal, &mut result)?;
        }

        Ok(result)
    }

    /// Attach a newly created sandbox to a workload, if policy allows, and audit the attempt.
    ///
    /// An explicit `openshell.nvidia.com/agent-id` label wins and needs an allowlisted
    /// principal. Without a label, and when principal derivation is on, the workload comes
    /// from the authenticated `(workspace, principal)`. Anything else stays unbound, so its
    /// traffic fails closed.
    fn bind_created_sandbox(
        &self,
        sandbox_id: &str,
        committed_response: &Value,
        principal: &HashMap<String, String>,
        result: &mut InterceptorResult,
    ) -> std::result::Result<(), Status> {
        let labeled = extract_agent_id(committed_response);
        if labeled.is_none() && !self.agent_binding.derive_from_principal {
            return Ok(());
        }
        let Some(workspace) = extract_workspace(committed_response) else {
            // Never assume a workspace: a wrong guess would merge or split workloads silently.
            tracing::warn!(%sandbox_id, "workload binding refused: the committed sandbox reports no workspace");
            let mut audit = BindingAudit {
                sandbox_id: sandbox_id.to_string(),
                workspace: String::new(),
                principal_kind: principal.get("kind").cloned().unwrap_or_default(),
                principal_provider: principal.get("provider").cloned().unwrap_or_default(),
                principal_subject: principal.get("subject").cloned().unwrap_or_default(),
                agent_id: None,
                source: if labeled.is_some() {
                    "label"
                } else {
                    "principal"
                },
                bound: false,
                reason: None,
            };
            self.refuse_binding(
                result,
                &mut audit,
                "refused",
                "the committed sandbox reports no workspace".into(),
            );
            return Ok(());
        };
        let kind = principal
            .get("kind")
            .map(String::as_str)
            .unwrap_or("unknown");
        let provider = principal.get("provider").map(String::as_str).unwrap_or("");
        let subject = principal
            .get("subject")
            .map(|subject| subject.trim())
            .unwrap_or("");
        let source = if labeled.is_some() {
            "label"
        } else {
            "principal"
        };
        let mut audit = BindingAudit {
            sandbox_id: sandbox_id.to_string(),
            workspace: workspace.clone(),
            principal_kind: kind.to_string(),
            principal_provider: provider.to_string(),
            principal_subject: subject.to_string(),
            agent_id: None,
            source,
            bound: false,
            reason: None,
        };

        let (agent_id, display_name, auto_register) = match labeled {
            Some(agent_id) => {
                audit.agent_id = Some(agent_id.clone());
                if !self.agent_binding.permits(principal) {
                    // The sandbox exists but stays unbound, so its traffic fails closed.
                    tracing::warn!(%sandbox_id, "workload binding refused: creating principal is not allowlisted");
                    self.refuse_binding(
                        result,
                        &mut audit,
                        "refused_principal",
                        "creating principal is not allowlisted".into(),
                    );
                    return Ok(());
                }
                (
                    agent_id,
                    extract_agent_name(committed_response),
                    self.agent_binding.auto_register_agents,
                )
            }
            None => match derive_workload(
                &workspace,
                provider,
                kind,
                subject,
                self.agent_binding.allow_local_dev_principal,
            ) {
                Ok(derived) => (derived.agent_id, Some(derived.display_name), true),
                Err(error) => {
                    tracing::warn!(%sandbox_id, %error, "workload derivation refused");
                    self.refuse_binding(result, &mut audit, "refused", error.to_string());
                    return Ok(());
                }
            },
        };
        audit.agent_id = Some(agent_id.clone());

        let agent_revision = extract_agent_revision(committed_response);
        let run_id = extract_run_id(committed_response, sandbox_id);
        match self.store.auto_bind_sandbox_epoch(&SandboxBinding {
            sandbox_id,
            gateway_id: &self.gateway_id,
            agent_id: &agent_id,
            agent_revision: &agent_revision,
            run_id: &run_id,
            auto_register,
            display_name: display_name.as_deref(),
            workspace: &workspace,
            claim_workspace: source == "principal",
        }) {
            Ok(()) => {
                result
                    .log_annotations
                    .insert("agent_id".to_string(), agent_id);
                result.log_annotations.insert("run_id".to_string(), run_id);
                result
                    .log_annotations
                    .insert("workspace".to_string(), workspace);
                result
                    .log_annotations
                    .insert("agent_binding_source".to_string(), source.to_string());
                audit.bound = true;
                self.audit_binding(&audit);
                Ok(())
            }
            Err(
                error @ (RiskGuardError::PermissionDenied(_) | RiskGuardError::InvalidArgument(_)),
            ) => {
                tracing::warn!(%sandbox_id, %error, "workload binding refused");
                self.refuse_binding(result, &mut audit, "refused", error.to_string());
                Ok(())
            }
            Err(error) => Err(risk_guard_error_to_status(error)),
        }
    }

    fn refuse_binding(
        &self,
        result: &mut InterceptorResult,
        audit: &mut BindingAudit,
        outcome: &str,
        reason: String,
    ) {
        result
            .log_annotations
            .insert("agent_binding".to_string(), outcome.to_string());
        result
            .log_annotations
            .insert("agent_binding_reason".to_string(), reason.clone());
        audit.reason = Some(reason);
        self.audit_binding(audit);
    }

    /// Audit failures must never block sandbox creation: the sandbox is already committed.
    fn audit_binding(&self, entry: &BindingAudit) {
        // OpenShell can replay a committed CreateSandbox, which would repeat the same attempt.
        if let Ok(previous) = self.store.list_binding_audit(&entry.sandbox_id)
            && previous.last() == Some(entry)
        {
            return;
        }
        if let Err(error) = self.store.record_binding_audit(entry) {
            tracing::warn!(sandbox_id = %entry.sandbox_id, %error, "could not record the workload binding audit");
        }
    }

    /// Control-plane non-expansion does not depend on the data-plane scoring mode:
    /// observe only stops request denials, never policy broadening.
    fn find_active_governed_epoch(
        &self,
        operation: &Value,
        current_state: Option<&Value>,
        principal: Option<&HashMap<String, String>>,
    ) -> std::result::Result<Option<EpochRecord>, Status> {
        let candidates = extract_sandbox_candidates(operation, current_state, principal);
        for candidate in candidates {
            if let Some(epoch) = self
                .store
                .get_effective_active_epoch(&candidate)
                .map_err(risk_guard_error_to_status)?
                && epoch.active
            {
                return Ok(Some(epoch));
            }
        }
        Ok(None)
    }

    fn check_required_middleware(
        &self,
        policy_yaml: Option<&str>,
        policy_obj: Option<&Value>,
    ) -> bool {
        if let Some(yaml) = policy_yaml {
            if let Ok(doc) = openshell_policy_schema::parse_policy(yaml)
                && doc.network_middlewares.iter().any(|(key, mw)| {
                    (matches_middleware_identifier(key, &self.required_middleware_name)
                        || matches_middleware_identifier(
                            &mw.middleware,
                            &self.required_middleware_name,
                        )
                        || matches_middleware_identifier(&mw.name, &self.required_middleware_name))
                        && is_fail_closed_str(&mw.on_error)
                })
            {
                return true;
            }
            if let Ok(val) = serde_yml::from_str::<Value>(yaml)
                && json_policy_has_required_middleware(&val, &self.required_middleware_name)
            {
                return true;
            }
            return false;
        }

        if let Some(obj) = policy_obj {
            return json_policy_has_required_middleware(obj, &self.required_middleware_name);
        }

        true
    }
}

#[tonic::async_trait]
impl GatewayInterceptor for RiskGuardInterceptorService {
    async fn describe(
        &self,
        request: Request<DescribeRequest>,
    ) -> std::result::Result<Response<InterceptorManifest>, Status> {
        if request.metadata().contains_key("authorization") {
            self.auth
                .verify_gateway_call(request.metadata())
                .map_err(risk_guard_error_to_status)?;
        }

        let manifest = self.manifest();
        validate_gateway_metadata(
            ExtensionFamily::GatewayInterceptor,
            EXTENSION_IMPLEMENTATION_NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;

        Ok(Response::new(manifest))
    }

    async fn snapshot_provider_profiles(
        &self,
        _request: Request<ProviderProfileSnapshotRequest>,
    ) -> std::result::Result<Response<ProviderProfileSnapshot>, Status> {
        Err(Status::unimplemented(
            "provider profile vending is not enabled",
        ))
    }

    async fn evaluate(
        &self,
        request: Request<InterceptorEvaluation>,
    ) -> std::result::Result<Response<InterceptorResult>, Status> {
        self.auth
            .verify_gateway_call(request.metadata())
            .map_err(risk_guard_error_to_status)?;

        let evaluation = request.into_inner();
        let method = resolve_method_name(&evaluation).to_string();
        let phase = evaluation
            .phase
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("interceptor phase is required"))?;

        let result = match phase {
            interceptor_evaluation::Phase::ModifyOperation(payload) => {
                let _operation = payload
                    .proposed_operation
                    .as_ref()
                    .map_or_else(|| Value::Object(Map::new()), struct_to_json);
                allow()
            }
            interceptor_evaluation::Phase::Validate(payload) => {
                let operation = payload
                    .proposed_operation
                    .as_ref()
                    .map_or_else(|| Value::Object(Map::new()), struct_to_json);
                let current_state = payload.current_state.as_ref().map(struct_to_json);
                self.evaluate_validate(
                    &method,
                    &operation,
                    current_state.as_ref(),
                    &evaluation.principal,
                )?
            }
            interceptor_evaluation::Phase::PostCommit(payload) => {
                let committed_response = payload
                    .committed_response
                    .as_ref()
                    .map_or_else(|| Value::Object(Map::new()), struct_to_json);
                self.evaluate_post_commit(&method, &committed_response, &evaluation.principal)?
            }
        };

        Ok(Response::new(result))
    }
}

fn validate_binding(id: &str, method: &str) -> InterceptorBinding {
    InterceptorBinding {
        id: id.to_string(),
        selector: Some(InterceptorSelector {
            rpc: format!("{OPENSHELL_SERVICE}/{method}"),
            service: OPENSHELL_SERVICE.to_string(),
            method: method.to_string(),
        }),
        phases: vec![GatewayInterceptorPhase::Validate as i32],
        failure_policy: "fail_closed".to_string(),
    }
}

fn post_commit_binding(id: &str, method: &str) -> InterceptorBinding {
    InterceptorBinding {
        id: id.to_string(),
        selector: Some(InterceptorSelector {
            rpc: format!("{OPENSHELL_SERVICE}/{method}"),
            service: OPENSHELL_SERVICE.to_string(),
            method: method.to_string(),
        }),
        phases: vec![GatewayInterceptorPhase::PostCommit as i32],
        failure_policy: "fail_open".to_string(),
    }
}

fn resolve_method_name(evaluation: &InterceptorEvaluation) -> &str {
    let raw = evaluation.method.trim();
    if !raw.is_empty() {
        return raw.rsplit('/').next().unwrap_or(raw);
    }
    match evaluation.binding_id.as_str() {
        "validate-create-sandbox" | "post-commit-create-sandbox" => "CreateSandbox",
        "validate-update-config" | "post-commit-update-config" => "UpdateConfig",
        "validate-approve-draft-chunk" | "post-commit-approve-draft-chunk" => "ApproveDraftChunk",
        "validate-approve-all-draft-chunks" | "post-commit-approve-all-draft-chunks" => {
            "ApproveAllDraftChunks"
        }
        "validate-submit-policy-analysis" | "post-commit-submit-policy-analysis" => {
            "SubmitPolicyAnalysis"
        }
        "post-commit-delete-sandbox" => "DeleteSandbox",
        "post-commit-stop-sandbox" => "StopSandbox",
        "post-commit-terminate-sandbox" => "TerminateSandbox",
        _ => "",
    }
}

fn allow() -> InterceptorResult {
    InterceptorResult {
        allowed: true,
        reason: String::new(),
        status_code: String::new(),
        patches: Vec::new(),
        log_annotations: HashMap::new(),
    }
}

fn deny(reason: &str) -> InterceptorResult {
    InterceptorResult {
        allowed: false,
        reason: reason.to_string(),
        status_code: "PERMISSION_DENIED".to_string(),
        patches: Vec::new(),
        log_annotations: HashMap::new(),
    }
}

fn risk_guard_error_to_status(err: RiskGuardError) -> Status {
    match err {
        RiskGuardError::Unauthenticated(msg) => Status::unauthenticated(msg),
        RiskGuardError::PermissionDenied(msg) => Status::permission_denied(msg),
        RiskGuardError::InvalidArgument(msg) => Status::invalid_argument(msg),
        RiskGuardError::ConflictingDuplicateRequestId { .. } => {
            Status::already_exists(err.to_string())
        }
        RiskGuardError::AdmissionExhausted(msg) => Status::resource_exhausted(msg),
        RiskGuardError::Storage(msg) => Status::internal(msg),
        RiskGuardError::Policy(msg) => Status::invalid_argument(msg),
        RiskGuardError::Internal(msg) => Status::internal(msg),
    }
}

fn requests_auto_proposal_approval(operation: &Value) -> bool {
    let setting_key = operation
        .get("setting_key")
        .or_else(|| operation.get("settingKey"))
        .and_then(Value::as_str);

    if setting_key == Some("proposal_approval_mode")
        && let Some(setting_value) = operation
            .get("setting_value")
            .or_else(|| operation.get("settingValue"))
    {
        return value_contains_auto(setting_value);
    }

    if let Some(mode_val) = operation.get("proposal_approval_mode").or_else(|| {
        operation
            .pointer("/settings/proposal_approval_mode")
            .or_else(|| operation.pointer("/spec/proposal_approval_mode"))
    }) {
        return value_contains_auto(mode_val);
    }

    false
}

fn value_contains_auto(val: &Value) -> bool {
    match val {
        Value::String(s) => s.to_ascii_lowercase().contains("auto"),
        Value::Object(map) => map.values().any(value_contains_auto),
        Value::Array(items) => items.iter().any(value_contains_auto),
        _ => false,
    }
}

fn extract_policy_yaml(val: &Value) -> Option<String> {
    let direct_candidates = [
        val.get("policy_yaml"),
        val.get("policyYaml"),
        val.pointer("/spec/policy_yaml"),
        val.pointer("/spec/policyYaml"),
        val.pointer("/sandbox/spec/policy_yaml"),
        val.pointer("/sandbox/spec/policyYaml"),
        val.get("policy").filter(|v| v.is_string()),
        val.pointer("/spec/policy").filter(|v| v.is_string()),
        val.pointer("/sandbox/spec/policy")
            .filter(|v| v.is_string()),
    ];
    for candidate in direct_candidates.into_iter().flatten() {
        if let Some(s) = candidate.as_str()
            && !s.trim().is_empty()
        {
            return Some(s.to_string());
        }
    }

    let annotation_containers = [
        val.get("annotations"),
        val.pointer("/metadata/annotations"),
        val.pointer("/sandbox/annotations"),
        val.pointer("/sandbox/metadata/annotations"),
        val.pointer("/spec/template/annotations"),
        val.pointer("/sandbox/spec/template/annotations"),
    ];
    for container in annotation_containers.into_iter().flatten() {
        if let Some(s) = container
            .get(POLICY_YAML_ANNOTATION)
            .or_else(|| container.get("policy_yaml"))
            .and_then(Value::as_str)
            && !s.trim().is_empty()
        {
            return Some(s.to_string());
        }
    }

    None
}

fn extract_policy_object(val: &Value) -> Option<&Value> {
    let candidates = [
        val.get("policy"),
        val.pointer("/spec/policy"),
        val.pointer("/sandbox/spec/policy"),
        val.get("candidate_effective_policy"),
        val.get("candidateEffectivePolicy"),
    ];
    candidates.into_iter().flatten().find(|v| v.is_object())
}

fn extract_authored_policy_yaml(val: &Value) -> std::result::Result<Option<String>, Status> {
    match extract_policy_yaml(val) {
        Some(yaml) => Ok(Some(yaml)),
        None => extract_policy_object(val)
            .map(policy_object_to_yaml)
            .transpose(),
    }
}

fn policy_object_to_yaml(policy_obj: &Value) -> std::result::Result<String, Status> {
    if let Ok(doc) =
        serde_json::from_value::<openshell_policy_schema::PolicyDocument>(policy_obj.clone())
    {
        return openshell_policy_schema::serialize_policy(&doc)
            .map_err(|err| Status::invalid_argument(format!("invalid authored policy: {err}")));
    }
    use prost::Message;
    let codec = openshell_gateway_interceptors::ProtoJsonCodec::openshell().map_err(|err| {
        Status::internal(format!("policy descriptor initialization failed: {err}"))
    })?;
    let bytes = codec
        .encode_json_to_message("openshell.sandbox.v1.SandboxPolicy", policy_obj)
        .map_err(|err| Status::invalid_argument(format!("invalid wire policy: {err}")))?;
    let policy = openshell_core::proto::sandbox::v1::SandboxPolicy::decode(bytes.as_slice())
        .map_err(|err| Status::invalid_argument(format!("invalid policy protobuf: {err}")))?;
    openshell_policy::serialize_sandbox_policy(&policy)
        .map_err(|err| Status::invalid_argument(format!("invalid sandbox policy: {err}")))
}

fn extract_policy_hash(val: &Value) -> Option<String> {
    let direct_candidates = [
        val.get("policy_hash"),
        val.get("policyHash"),
        val.pointer("/sandbox/status/policy_hash"),
        val.pointer("/sandbox/status/policyHash"),
    ];
    for candidate in direct_candidates.into_iter().flatten() {
        if let Some(s) = candidate.as_str()
            && !s.trim().is_empty()
        {
            return Some(s.to_string());
        }
    }

    let annotation_containers = [
        val.get("annotations"),
        val.pointer("/metadata/annotations"),
        val.pointer("/sandbox/annotations"),
        val.pointer("/sandbox/metadata/annotations"),
        val.pointer("/spec/template/annotations"),
        val.pointer("/sandbox/spec/template/annotations"),
    ];
    for container in annotation_containers.into_iter().flatten() {
        if let Some(s) = container
            .get(POLICY_HASH_ANNOTATION)
            .or_else(|| container.get("policy_hash"))
            .and_then(Value::as_str)
            && !s.trim().is_empty()
        {
            return Some(s.to_string());
        }
    }

    None
}

fn extract_task_profile(val: &Value) -> Option<String> {
    let candidates = [
        val.get("task_profile"),
        val.get("taskProfile"),
        val.pointer("/sandbox/metadata/labels/openshell.nvidia.com~1task-profile"),
        val.pointer("/sandbox/metadata/annotations/openshell.nvidia.com~1task-profile"),
        val.pointer("/annotations/openshell.nvidia.com~1task-profile"),
        val.pointer("/labels/openshell.nvidia.com~1task-profile"),
    ];
    for candidate in candidates.into_iter().flatten() {
        if let Some(s) = candidate.as_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn policy_scoring_context(
    yaml: &str,
    middleware_name: &str,
) -> std::result::Result<(Option<String>, EnforcementMode), Status> {
    let policy = openshell_policy_schema::parse_policy(yaml)
        .map_err(|error| Status::invalid_argument(format!("invalid committed policy: {error}")))?;
    let mut context = None;
    for binding in policy
        .network_middlewares
        .values()
        .filter(|binding| binding.middleware == middleware_name)
    {
        let profile = match binding.config.get("task_profile") {
            Some(Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
            None => None,
            _ => {
                return Err(Status::invalid_argument(
                    "risk-guard task_profile must be a nonempty string",
                ));
            }
        };
        let mode = match binding.config.get("mode") {
            Some(Value::String(value)) if value == "observe" => EnforcementMode::Observe,
            Some(Value::String(value)) if value == "enforce" => EnforcementMode::Enforce,
            None => EnforcementMode::Enforce,
            _ => {
                return Err(Status::invalid_argument(
                    "risk-guard mode must be observe or enforce",
                ));
            }
        };
        let candidate = (profile, mode);
        if context
            .as_ref()
            .is_some_and(|existing| existing != &candidate)
        {
            return Err(Status::invalid_argument(
                "risk-guard bindings must use one scoring profile and mode",
            ));
        }
        context = Some(candidate);
    }
    Ok(context.unwrap_or((None, EnforcementMode::Enforce)))
}

#[cfg(test)]
mod guardrail_policy_context_tests {
    use super::*;

    #[test]
    fn exported_profile_references_and_observe_mode_are_resolved_from_policy() {
        let yaml = "version: 1\nnetwork_middlewares:\n  risk:\n    middleware: risk-guard\n    on_error: fail_closed\n    config: {task_profile: approved-profile-hash, mode: observe}\n";
        assert_eq!(
            policy_scoring_context(yaml, "risk-guard").unwrap(),
            (
                Some("approved-profile-hash".into()),
                EnforcementMode::Observe
            ),
        );
    }

    #[test]
    fn invalid_policy_modes_do_not_silently_fall_back_to_enforce() {
        let yaml = "version: 1\nnetwork_middlewares:\n  risk:\n    middleware: risk-guard\n    on_error: fail_closed\n    config: {task_profile: approved, mode: unexpected}\n";
        assert!(policy_scoring_context(yaml, "risk-guard").is_err());
    }
}

fn extract_post_commit_sandbox_id(committed_response: &Value) -> Option<String> {
    let candidates = [
        committed_response.pointer("/sandbox/metadata/id"),
        committed_response.get("sandbox_id"),
        committed_response.get("sandboxId"),
        committed_response.get("id"),
        committed_response.pointer("/sandbox/id"),
        committed_response.pointer("/metadata/id"),
        committed_response.pointer("/sandbox/metadata/name"),
        committed_response.pointer("/metadata/name"),
        committed_response.get("sandbox").filter(|v| v.is_string()),
        committed_response.get("name").filter(|v| v.is_string()),
    ];
    for candidate in candidates.into_iter().flatten() {
        if let Some(s) = candidate.as_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Read an agent-binding value from label/annotation containers only, and only under its
/// exact `openshell.nvidia.com/` key. Bare names such as `agent_id` are never honored.
fn extract_annotation(val: &Value, key: &str) -> Option<String> {
    let containers = [
        val.get("annotations"),
        val.pointer("/metadata/annotations"),
        val.pointer("/sandbox/annotations"),
        val.pointer("/sandbox/metadata/annotations"),
        val.pointer("/spec/template/annotations"),
        val.pointer("/sandbox/spec/template/annotations"),
        val.get("labels"),
        val.pointer("/metadata/labels"),
        val.pointer("/sandbox/labels"),
        val.pointer("/sandbox/metadata/labels"),
        val.pointer("/spec/template/labels"),
        val.pointer("/sandbox/spec/template/labels"),
    ];
    containers
        .into_iter()
        .flatten()
        .filter_map(|container| container.get(key).and_then(Value::as_str))
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

fn binding_annotations_present(val: &Value) -> bool {
    [
        AGENT_ID_ANNOTATION,
        AGENT_NAME_ANNOTATION,
        AGENT_REVISION_ANNOTATION,
        RUN_ID_ANNOTATION,
    ]
    .into_iter()
    .any(|key| extract_annotation(val, key).is_some())
}

/// The workspace that owns a committed sandbox, as the gateway reports it. OpenShell
/// normalizes an empty workspace to `default` before persisting, so a response without one
/// is unexpected and is refused rather than guessed.
fn extract_workspace(committed_response: &Value) -> Option<String> {
    [
        committed_response.pointer("/sandbox/metadata/workspace"),
        committed_response.pointer("/metadata/workspace"),
        committed_response.get("workspace"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .map(str::trim)
    .find(|workspace| !workspace.is_empty())
    .map(str::to_string)
}

fn extract_agent_id(committed_response: &Value) -> Option<String> {
    extract_annotation(committed_response, AGENT_ID_ANNOTATION)
}

/// The optional readable name for a labeled workload. It is display text only, so it is bounded and must not
/// contain control characters; anything else is ignored rather than refusing the sandbox.
fn extract_agent_name(committed_response: &Value) -> Option<String> {
    extract_annotation(committed_response, AGENT_NAME_ANNOTATION)
        .filter(|name| name.len() <= 256 && !name.chars().any(char::is_control))
}

fn extract_agent_revision(committed_response: &Value) -> String {
    extract_annotation(committed_response, AGENT_REVISION_ANNOTATION)
        .unwrap_or_else(|| "v1".to_string())
}

fn extract_run_id(committed_response: &Value, sandbox_id: &str) -> String {
    extract_annotation(committed_response, RUN_ID_ANNOTATION)
        .unwrap_or_else(|| format!("run-{sandbox_id}"))
}

fn extract_sandbox_candidates(
    operation: &Value,
    current_state: Option<&Value>,
    principal: Option<&HashMap<String, String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_unique = |raw: &str| {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    };

    let op_candidates = [
        operation.get("sandbox_id"),
        operation.get("sandboxId"),
        operation.get("sandbox").filter(|v| v.is_string()),
        operation.get("name").filter(|v| v.is_string()),
        operation.pointer("/sandbox/metadata/id"),
        operation.pointer("/sandbox/id"),
        operation.pointer("/sandbox/metadata/name"),
        operation.pointer("/metadata/id"),
        operation.pointer("/metadata/name"),
    ];
    for candidate in op_candidates.into_iter().flatten() {
        if let Some(s) = candidate.as_str() {
            push_unique(s);
        }
    }

    if let Some(state) = current_state {
        let state_candidates = [
            state.get("sandbox_id"),
            state.get("sandboxId"),
            state.get("sandbox").filter(|v| v.is_string()),
            state.pointer("/sandbox/metadata/id"),
            state.pointer("/sandbox/id"),
            state.pointer("/sandbox/metadata/name"),
            state.pointer("/metadata/id"),
            state.pointer("/metadata/name"),
        ];
        for candidate in state_candidates.into_iter().flatten() {
            if let Some(s) = candidate.as_str() {
                push_unique(s);
            }
        }
    }

    if let Some(principal_map) = principal {
        for key in ["sandbox_id", "sandbox", "name", "sub"] {
            if let Some(val) = principal_map.get(key) {
                let stripped = val
                    .strip_prefix("spiffe://openshell/sandbox/")
                    .unwrap_or(val.as_str());
                push_unique(stripped);
            }
        }
    }

    out
}

fn json_policy_has_required_middleware(policy_obj: &Value, required_name: &str) -> bool {
    let Some(middlewares) = policy_obj
        .get("network_middlewares")
        .or_else(|| policy_obj.get("networkMiddlewares"))
    else {
        return false;
    };

    match middlewares {
        Value::Object(map) => {
            if map.is_empty() {
                return false;
            }
            map.iter().any(|(key, entry)| {
                middleware_entry_matches(Some(key.as_str()), entry, required_name)
            })
        }
        Value::Array(items) => {
            if items.is_empty() {
                return false;
            }
            items
                .iter()
                .any(|entry| middleware_entry_matches(None, entry, required_name))
        }
        _ => false,
    }
}

fn middleware_entry_matches(key: Option<&str>, entry: &Value, required_name: &str) -> bool {
    let key_matches = key.is_some_and(|k| matches_middleware_identifier(k, required_name));
    let mw_field_matches = entry
        .get("middleware")
        .and_then(Value::as_str)
        .is_some_and(|m| matches_middleware_identifier(m, required_name));
    let name_field_matches = entry
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|n| matches_middleware_identifier(n, required_name));

    if !(key_matches || mw_field_matches || name_field_matches) {
        return false;
    }

    let on_error_val = entry.get("on_error").or_else(|| entry.get("onError"));
    match on_error_val {
        Some(Value::String(s)) => is_fail_closed_str(s),
        Some(Value::Number(n)) => {
            n.as_i64() == Some(1) || n.as_u64() == Some(1) || n.as_f64() == Some(1.0)
        }
        _ => false,
    }
}

fn matches_middleware_identifier(candidate: &str, required: &str) -> bool {
    let candidate = candidate.trim();
    let required = required.trim();
    if candidate.is_empty() || required.is_empty() {
        return false;
    }
    if candidate.eq_ignore_ascii_case(required) {
        return true;
    }
    let candidate_norm = candidate.replace('_', "-").to_ascii_lowercase();
    let required_norm = required.replace('_', "-").to_ascii_lowercase();
    candidate_norm == required_norm || candidate_norm == format!("openshell-{required_norm}")
}

fn is_fail_closed_str(val: &str) -> bool {
    let trimmed = val.trim();
    trimmed.eq_ignore_ascii_case("fail_closed")
        || trimmed.eq_ignore_ascii_case("NETWORK_MIDDLEWARE_FAILURE_POLICY_FAIL_CLOSED")
        || trimmed == "1"
}

pub fn struct_to_json(value: &Struct) -> Value {
    Value::Object(
        value
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), proto_value_to_json(value)))
            .collect(),
    )
}

pub fn json_to_struct(value: &Value) -> std::result::Result<Struct, String> {
    let Value::Object(fields) = value else {
        return Err("JSON value must be an object".to_string());
    };
    Ok(Struct {
        fields: fields
            .iter()
            .map(|(key, value)| json_to_proto_value(value).map(|value| (key.clone(), value)))
            .collect::<std::result::Result<_, _>>()?,
    })
}

fn json_to_proto_value(value: &Value) -> std::result::Result<ProtoValue, String> {
    let kind = match value {
        Value::Null => Kind::NullValue(0),
        Value::Bool(value) => Kind::BoolValue(*value),
        Value::Number(value) => Kind::NumberValue(
            value
                .as_f64()
                .ok_or_else(|| "invalid JSON number".to_string())?,
        ),
        Value::String(value) => Kind::StringValue(value.clone()),
        Value::Array(values) => Kind::ListValue(ListValue {
            values: values
                .iter()
                .map(json_to_proto_value)
                .collect::<std::result::Result<_, _>>()?,
        }),
        Value::Object(fields) => Kind::StructValue(Struct {
            fields: fields
                .iter()
                .map(|(key, value)| json_to_proto_value(value).map(|value| (key.clone(), value)))
                .collect::<std::result::Result<_, _>>()?,
        }),
    };
    Ok(ProtoValue { kind: Some(kind) })
}

fn proto_value_to_json(value: &ProtoValue) -> Value {
    match value.kind.as_ref() {
        Some(Kind::NullValue(_)) | None => Value::Null,
        Some(Kind::NumberValue(value)) => {
            if value.is_finite()
                && value.fract() == 0.0
                && *value >= (i64::MIN as f64)
                && *value <= (i64::MAX as f64)
            {
                #[allow(clippy::cast_possible_truncation)]
                let int_val = *value as i64;
                Value::Number(Number::from(int_val))
            } else {
                Number::from_f64(*value).map_or(Value::Null, Value::Number)
            }
        }
        Some(Kind::StringValue(value)) => Value::String(value.clone()),
        Some(Kind::BoolValue(value)) => Value::Bool(*value),
        Some(Kind::StructValue(value)) => struct_to_json(value),
        Some(Kind::ListValue(value)) => {
            Value::Array(value.values.iter().map(proto_value_to_json).collect())
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{JwtAuthVerifier, JwtTestIssuer};
    use crate::hardening::ProverHardeningEngine;
    use crate::store::SqliteRiskStore;
    use openshell_core::extension_protocol::gateway_metadata;
    use openshell_core::proto::gateway_interceptor::v1::{
        ModifyOperationEvaluation, PostCommitEvaluation, ValidateEvaluation,
    };
    use serde_json::json;
    use tonic::metadata::AsciiMetadataValue;

    const TEST_GATEWAY_ID: &str = "gw-test-01";
    const TEST_AUDIENCE: &str = "grpc://risk-guard.local:50055";
    const TEST_TASK_PROFILE: &str = "github_docs_triage";

    fn setup_service_with_jwt() -> (RiskGuardInterceptorService, Arc<SqliteRiskStore>, String) {
        let issuer = JwtTestIssuer::new(TEST_GATEWAY_ID);
        let auth = Arc::new(
            JwtAuthVerifier::from_ed25519_pem(
                TEST_GATEWAY_ID,
                TEST_AUDIENCE,
                issuer.public_key_pem(),
            )
            .expect("valid Ed25519 verifier"),
        );
        let store = Arc::new(SqliteRiskStore::open_in_memory().expect("in-memory store"));
        let hardening = Arc::new(ProverHardeningEngine::new());

        let service = RiskGuardInterceptorService::new(
            auth,
            store.clone(),
            hardening,
            TEST_GATEWAY_ID,
            TEST_AUDIENCE,
            TEST_TASK_PROFILE,
        );

        let token = issuer
            .mint_gateway_token(TEST_AUDIENCE, 60)
            .expect("mint gateway token");

        (service, store, token)
    }

    fn authenticated_request<T>(inner: T, token: &str) -> Request<T> {
        let mut req = Request::new(inner);
        let header_val =
            AsciiMetadataValue::try_from(format!("Bearer {token}")).expect("valid bearer header");
        req.metadata_mut().insert("authorization", header_val);
        req
    }

    #[test]
    fn control_plane_approvals_are_guarded_in_observe_and_enforce_modes() {
        let (service, store, _) = setup_service_with_jwt();
        let mut baseline = crate::fixture::build_standard_corpus().default_baseline;
        baseline.task_profile = TEST_TASK_PROFILE.into();
        baseline.normalizer_version = crate::normalizer::DEFAULT_NORMALIZER_VERSION.into();
        let hash = store.store_baseline(&baseline).unwrap();
        store.register_agent("mode-agent", "Mode test").unwrap();
        store
            .create_agent_run(
                "mode-agent",
                "mode-run",
                "revision-1",
                TEST_TASK_PROFILE,
                EnforcementMode::Observe,
            )
            .unwrap();
        store
            .upsert_epoch(&EpochRecord {
                epoch_id: "mode-epoch".into(),
                gateway_id: TEST_GATEWAY_ID.into(),
                sandbox_id: "mode-sandbox".into(),
                task_profile: TEST_TASK_PROFILE.into(),
                baseline_hash: hash,
                mode: EnforcementMode::Observe,
                active: true,
                next_sequence: 1,
                created_at_ms: 0,
                credentialed_endpoints: Default::default(),
                active_policy_hash: None,
            })
            .unwrap();
        store
            .bind_agent_run("mode-run", "mode-sandbox", TEST_GATEWAY_ID)
            .unwrap();
        let operation = json!({"sandbox_id":"mode-sandbox"});
        let proposal = json!({"sandbox_id":"mode-sandbox","proposed_chunks":[{"rule":"expand"}]});
        let principal = HashMap::new();
        // Observe mode stops request denials only; it must not reopen policy broadening.
        assert!(
            !service
                .evaluate_validate("ApproveAllDraftChunks", &operation, None, &principal)
                .unwrap()
                .allowed
        );
        assert!(
            !service
                .evaluate_validate("ApproveDraftChunk", &operation, None, &principal)
                .unwrap()
                .allowed
        );
        assert!(
            !service
                .evaluate_validate("SubmitPolicyAnalysis", &proposal, None, &principal)
                .unwrap()
                .allowed
        );
        let view = store
            .agent_guardrails("mode-agent", 60_000)
            .unwrap()
            .unwrap();
        let mut settings: crate::guardrails::AgentGuardrails =
            serde_json::from_value(view["settings"].clone()).unwrap();
        settings.mode = EnforcementMode::Enforce;
        store
            .save_agent_guardrails(
                "mode-agent",
                &crate::guardrails::GuardrailsUpdate {
                    expected_revision: 0,
                    settings,
                },
                "test-operator",
                60_000,
            )
            .unwrap();
        assert!(
            !service
                .evaluate_validate("ApproveAllDraftChunks", &operation, None, &principal)
                .unwrap()
                .allowed
        );
        assert!(
            !service
                .evaluate_validate("ApproveDraftChunk", &operation, None, &principal)
                .unwrap()
                .allowed
        );
        assert_eq!(
            store
                .get_active_epoch("mode-sandbox")
                .unwrap()
                .unwrap()
                .mode,
            EnforcementMode::Observe
        );
        assert_eq!(
            store
                .get_effective_active_epoch("mode-sandbox")
                .unwrap()
                .unwrap()
                .mode,
            EnforcementMode::Enforce
        );
    }

    #[tokio::test]
    async fn describe_returns_valid_bindings_with_separate_validate_and_post_commit_policies() {
        let (service, _store, token) = setup_service_with_jwt();

        let req = authenticated_request(
            DescribeRequest {
                gateway: Some(gateway_metadata(ExtensionFamily::GatewayInterceptor)),
            },
            &token,
        );

        let manifest = service
            .describe(req)
            .await
            .expect("describe should succeed")
            .into_inner();

        assert_eq!(manifest.name, "risk-guard-governance");
        assert_eq!(manifest.failure_policy, "fail_closed");
        assert!(!manifest.provider_profiles);
        assert_eq!(manifest.expected_audience, TEST_AUDIENCE);
        assert!(manifest.extension.is_some());

        for method in [
            "CreateSandbox",
            "UpdateConfig",
            "ApproveDraftChunk",
            "ApproveAllDraftChunks",
            "SubmitPolicyAnalysis",
        ] {
            let expected_rpc = format!("openshell.v1.OpenShell/{method}");
            let validate_b = manifest
                .bindings
                .iter()
                .find(|b| {
                    b.selector.as_ref().is_some_and(|s| s.rpc == expected_rpc)
                        && b.phases == vec![GatewayInterceptorPhase::Validate as i32]
                })
                .unwrap_or_else(|| panic!("missing Validate binding for {method}"));
            assert_eq!(validate_b.failure_policy, "fail_closed");

            let post_commit_b = manifest
                .bindings
                .iter()
                .find(|b| {
                    b.selector.as_ref().is_some_and(|s| s.rpc == expected_rpc)
                        && b.phases == vec![GatewayInterceptorPhase::PostCommit as i32]
                })
                .unwrap_or_else(|| panic!("missing PostCommit binding for {method}"));
            assert_eq!(post_commit_b.failure_policy, "fail_open");
        }
    }

    #[tokio::test]
    async fn validate_update_config_blocks_proposal_approval_mode_auto() {
        let (service, _store, token) = setup_service_with_jwt();

        let proposed = json_to_struct(&json!({
            "sandbox": "sb-governed-1",
            "setting_key": "proposal_approval_mode",
            "setting_value": {
                "string_value": "auto"
            }
        }))
        .expect("valid struct");

        let eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-update-config".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "UpdateConfig".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::Validate(
                ValidateEvaluation {
                    proposed_operation: Some(proposed),
                    current_state: None,
                },
            )),
        };

        let result = service
            .evaluate(authenticated_request(eval, &token))
            .await
            .expect("evaluate should succeed")
            .into_inner();

        assert!(!result.allowed);
        assert_eq!(result.status_code, "PERMISSION_DENIED");
        assert_eq!(
            result.reason,
            "risk-guard forbids proposal_approval_mode=auto on governed sandboxes"
        );
    }

    #[tokio::test]
    async fn validate_update_config_blocks_middleware_removal_and_policy_widening_but_allows_narrowing()
     {
        let (service, store, token) = setup_service_with_jwt();
        let sandbox_id = "sb-monotonic-01";

        let full_policy_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/gh
"#;

        let read_only_policy_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/gh
"#;

        let narrowed_policy_yaml = r#"
version: 1
filesystem_policy:
  include_workdir: false
  read_only: [/usr]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  risk_guard:
    middleware: risk-guard
    on_error: fail_closed
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/org/docs-site
    binaries:
      - path: /usr/bin/gh
"#;

        let missing_mw_policy_yaml = r#"
version: 1
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/org/docs-site
"#;

        // 1. Seed initial full policy snapshot and verify valid narrowing (full -> narrow GET /repos/org/docs-site) is allowed.
        store
            .record_policy_snapshot(
                sandbox_id,
                &sha256_hex(full_policy_yaml.as_bytes()),
                full_policy_yaml,
                &BTreeSet::new(),
                "create_sandbox",
                1_000,
            )
            .expect("record initial full snapshot");

        let narrow_op = json_to_struct(&json!({
            "sandbox": sandbox_id,
            "policy_yaml": narrowed_policy_yaml,
        }))
        .expect("valid struct");

        let narrow_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-update-config".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "UpdateConfig".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::Validate(
                ValidateEvaluation {
                    proposed_operation: Some(narrow_op),
                    current_state: None,
                },
            )),
        };

        let narrow_res = service
            .evaluate(authenticated_request(narrow_eval, &token))
            .await
            .expect("evaluate narrowing")
            .into_inner();
        assert!(
            narrow_res.allowed,
            "expected valid policy narrowing to be allowed, got: {}",
            narrow_res.reason
        );

        // 2. Removing risk-guard middleware is rejected.
        let remove_mw_op = json_to_struct(&json!({
            "sandbox": sandbox_id,
            "policy_yaml": missing_mw_policy_yaml,
        }))
        .expect("valid struct");

        let remove_mw_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-update-config".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "UpdateConfig".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::Validate(
                ValidateEvaluation {
                    proposed_operation: Some(remove_mw_op),
                    current_state: None,
                },
            )),
        };

        let remove_mw_res = service
            .evaluate(authenticated_request(remove_mw_eval, &token))
            .await
            .expect("evaluate middleware removal")
            .into_inner();
        assert!(!remove_mw_res.allowed);
        assert_eq!(remove_mw_res.status_code, "PERMISSION_DENIED");
        assert_eq!(
            remove_mw_res.reason,
            "governed sandbox policy must retain fail_closed risk-guard middleware binding"
        );

        // 3. Seed read-only policy snapshot and verify widening (access: read-only -> access: full) is rejected by Two-Step Containment Proof.
        store
            .record_policy_snapshot(
                sandbox_id,
                &sha256_hex(read_only_policy_yaml.as_bytes()),
                read_only_policy_yaml,
                &BTreeSet::new(),
                "update_config",
                2_000,
            )
            .expect("record read-only snapshot");

        let widen_op = json_to_struct(&json!({
            "sandbox": sandbox_id,
            "policy_yaml": full_policy_yaml,
        }))
        .expect("valid struct");

        let widen_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-update-config".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "UpdateConfig".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::Validate(
                ValidateEvaluation {
                    proposed_operation: Some(widen_op),
                    current_state: None,
                },
            )),
        };

        let widen_res = service
            .evaluate(authenticated_request(widen_eval, &token))
            .await
            .expect("evaluate widening")
            .into_inner();
        assert!(!widen_res.allowed);
        assert_eq!(widen_res.status_code, "PERMISSION_DENIED");
        assert!(
            widen_res
                .reason
                .starts_with("control-plane monotonicity violation: candidate policy expands permissions beyond current epoch boundary"),
            "unexpected reason: {}",
            widen_res.reason
        );
    }

    #[tokio::test]
    async fn post_commit_accepts_native_protojson_policy() {
        let (service, store, _) = setup_service_with_jwt();
        let mut baseline = crate::fixture::build_standard_corpus().default_baseline;
        baseline.task_profile = TEST_TASK_PROFILE.to_string();
        store.store_baseline(&baseline).unwrap();
        let policy = openshell_policy::parse_sandbox_policy(
            "version: 1\nfilesystem_policy:\n  include_workdir: false\n  read_only: [/usr]\n",
        )
        .unwrap();
        let codec = openshell_gateway_interceptors::ProtoJsonCodec::openshell().unwrap();
        let wire_policy = codec
            .decode_message_to_json("openshell.sandbox.v1.SandboxPolicy", &policy)
            .unwrap();
        service
            .post_commit_sandbox_mutation(
                "CreateSandbox",
                &json!({"sandbox": {"id": "native-policy", "spec": {"policy": wire_policy}}}),
                &HashMap::new(),
            )
            .expect("native ProtoJSON must become canonical authored policy");
        assert!(store.get_active_epoch("native-policy").unwrap().is_some());
        assert!(
            store
                .latest_policy_snapshot("native-policy")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn post_commit_missing_baseline_does_not_fabricate_an_epoch() {
        let (mut service, store, _token) = setup_service_with_jwt();
        service.default_task_profile = "not-provisioned".to_string();
        let error = service
            .post_commit_sandbox_mutation(
                "CreateSandbox",
                &json!({"sandbox": {"metadata": {"id": "unprovisioned"}}}),
                &HashMap::new(),
            )
            .expect_err("missing baseline must be explicit");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(store.get_active_epoch("unprovisioned").unwrap().is_none());
    }

    #[tokio::test]
    async fn post_commit_create_sandbox_registers_epoch_and_records_snapshot_and_credentialed_endpoints()
     {
        let (service, store, token) = setup_service_with_jwt();
        let mut baseline = crate::fixture::build_standard_corpus().default_baseline;
        baseline.task_profile = TEST_TASK_PROFILE.to_string();
        store
            .store_baseline(&baseline)
            .expect("provision test baseline");
        let sandbox_id = "sb-postcommit-01";

        let policy_yaml = r#"
version: 1
network_middlewares:
  risk_guard:
    middleware: risk-guard
    on_error: fail_closed
network_policies:
  _provider_github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - path: /usr/bin/gh
"#;

        let committed_response = json_to_struct(&json!({
            "sandbox": {
                "metadata": {
                    "workspace": "default",
                    "id": sandbox_id,
                    "name": "docs-sandbox"
                }
            },
            "policy_yaml": policy_yaml
        }))
        .expect("valid struct");

        let eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "post-commit-create-sandbox".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "CreateSandbox".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::PostCommit(
                PostCommitEvaluation {
                    committed_response: Some(committed_response),
                },
            )),
        };

        let res = service
            .evaluate(authenticated_request(eval, &token))
            .await
            .expect("post_commit evaluate should succeed")
            .into_inner();
        assert!(res.allowed);

        // Verify EpochRecord was registered with credentialed endpoints and policy hash.
        let epoch = store
            .get_active_epoch(sandbox_id)
            .expect("query active epoch")
            .expect("active epoch should exist");
        assert_eq!(epoch.epoch_id, format!("ep_{sandbox_id}_1"));
        assert_eq!(epoch.gateway_id, TEST_GATEWAY_ID);
        assert_eq!(epoch.sandbox_id, sandbox_id);
        assert_eq!(epoch.task_profile, TEST_TASK_PROFILE);
        assert_eq!(epoch.mode, EnforcementMode::Enforce);
        assert!(epoch.active);
        assert!(
            epoch
                .credentialed_endpoints
                .contains(&("api.github.com".to_string(), 443))
        );
        assert_eq!(
            epoch.active_policy_hash.as_deref(),
            Some(sha256_hex(policy_yaml.as_bytes()).as_str())
        );

        // Verify policy_snapshots was recorded in SQLite.
        let (stored_hash, stored_yaml) = store
            .latest_policy_snapshot(sandbox_id)
            .expect("query latest policy snapshot")
            .expect("policy snapshot should exist");
        assert_eq!(stored_hash, sha256_hex(policy_yaml.as_bytes()));
        assert_eq!(stored_yaml, policy_yaml);

        // Verify ApproveAllDraftChunks is blocked while this active Enforce epoch is running.
        let approve_all_op = json_to_struct(&json!({
            "sandbox": sandbox_id,
        }))
        .expect("valid struct");
        let approve_all_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-approve-all-draft-chunks".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "ApproveAllDraftChunks".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::Validate(
                ValidateEvaluation {
                    proposed_operation: Some(approve_all_op),
                    current_state: None,
                },
            )),
        };
        let approve_all_res = service
            .evaluate(authenticated_request(approve_all_eval, &token))
            .await
            .expect("evaluate ApproveAllDraftChunks")
            .into_inner();
        assert!(!approve_all_res.allowed);
        assert_eq!(approve_all_res.status_code, "PERMISSION_DENIED");

        // Verify ModifyOperation is a no-op allow.
        let mod_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-create-sandbox".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "CreateSandbox".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::ModifyOperation(
                ModifyOperationEvaluation {
                    proposed_operation: Some(Struct::default()),
                },
            )),
        };
        let mod_res = service
            .evaluate(authenticated_request(mod_eval, &token))
            .await
            .expect("evaluate ModifyOperation")
            .into_inner();
        assert!(mod_res.allowed);
    }

    #[tokio::test]
    async fn validate_create_sandbox_and_draft_rpc_guards_and_auth_checks() {
        let (service, _store, token) = setup_service_with_jwt();

        // 1. snapshot_provider_profiles returns UNIMPLEMENTED
        let snap_err = service
            .snapshot_provider_profiles(Request::new(ProviderProfileSnapshotRequest {}))
            .await
            .expect_err("snapshot_provider_profiles must be unimplemented");
        assert_eq!(snap_err.code(), tonic::Code::Unimplemented);

        // 2. Unauthenticated evaluate returns UNAUTHENTICATED
        let unauth_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-create-sandbox".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "CreateSandbox".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::Validate(
                ValidateEvaluation {
                    proposed_operation: Some(Struct::default()),
                    current_state: None,
                },
            )),
        };
        let unauth_err = service
            .evaluate(Request::new(unauth_eval))
            .await
            .expect_err("missing bearer token must be rejected");
        assert_eq!(unauth_err.code(), tonic::Code::Unauthenticated);

        // 3. CreateSandbox with policy missing risk-guard middleware is denied
        let bad_create_op = json_to_struct(&json!({
            "spec": {
                "policy": {
                    "version": 1,
                    "network_middlewares": {
                        "other": {
                            "middleware": "other-mw",
                            "on_error": "fail_open"
                        }
                    }
                }
            }
        }))
        .expect("valid struct");
        let bad_create_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-create-sandbox".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "CreateSandbox".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::Validate(
                ValidateEvaluation {
                    proposed_operation: Some(bad_create_op),
                    current_state: None,
                },
            )),
        };
        let bad_create_res = service
            .evaluate(authenticated_request(bad_create_eval, &token))
            .await
            .expect("evaluate bad CreateSandbox")
            .into_inner();
        assert!(!bad_create_res.allowed);
        assert_eq!(
            bad_create_res.reason,
            "governed sandbox policy must retain fail_closed risk-guard middleware binding"
        );

        // 4. CreateSandbox with fail_closed risk-guard middleware is allowed
        let good_create_op = json_to_struct(&json!({
            "spec": {
                "policy": {
                    "version": 1,
                    "network_middlewares": {
                        "risk_guard": {
                            "middleware": "risk-guard",
                            "on_error": "fail_closed"
                        }
                    }
                }
            }
        }))
        .expect("valid struct");
        let good_create_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "validate-create-sandbox".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "CreateSandbox".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::Validate(
                ValidateEvaluation {
                    proposed_operation: Some(good_create_op),
                    current_state: None,
                },
            )),
        };
        let good_create_res = service
            .evaluate(authenticated_request(good_create_eval, &token))
            .await
            .expect("evaluate good CreateSandbox")
            .into_inner();
        assert!(good_create_res.allowed);
    }

    fn principal_of(kind: &str, subject: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("kind".to_string(), kind.to_string());
        if !subject.is_empty() {
            map.insert("subject".to_string(), subject.to_string());
        }
        match kind {
            "user" => {
                map.insert("provider".to_string(), "oidc".to_string());
            }
            "operator" => {
                map.insert("provider".to_string(), "mtls".to_string());
            }
            _ => {}
        }
        map
    }

    fn provision_baseline(store: &SqliteRiskStore) {
        let mut baseline = crate::fixture::build_standard_corpus().default_baseline;
        baseline.task_profile = TEST_TASK_PROFILE.to_string();
        store
            .store_baseline(&baseline)
            .expect("provision test baseline");
    }

    async fn create_with_annotations(
        service: &RiskGuardInterceptorService,
        token: &str,
        principal: HashMap<String, String>,
        sandbox_id: &str,
        annotations: Value,
    ) -> InterceptorResult {
        let committed = json_to_struct(&json!({
            "sandbox": {
                "metadata": {
                    "workspace": "default",
                    "id": sandbox_id,
                    "name": sandbox_id,
                    "annotations": annotations
                }
            }
        }))
        .expect("valid struct");
        let evaluation = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "post-commit-create-sandbox".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "CreateSandbox".to_string(),
            principal,
            phase: Some(interceptor_evaluation::Phase::PostCommit(
                PostCommitEvaluation {
                    committed_response: Some(committed),
                },
            )),
        };
        service
            .evaluate(authenticated_request(evaluation, token))
            .await
            .expect("post_commit evaluation")
            .into_inner()
    }

    fn binding_outcome(result: &InterceptorResult) -> Option<&str> {
        result
            .log_annotations
            .get("agent_binding")
            .map(String::as_str)
    }

    #[test]
    fn agent_binding_policy_accepts_only_exact_operator_or_user_entries() {
        assert!(AgentBindingPolicy::new(["operator:alice", "user:bob@example.com"], false).is_ok());
        for bad in [
            "alice",
            "operator:",
            "sandbox:sb-1",
            "peer:replica-1",
            "anonymous:x",
            "operator:*",
            "user:ali ce",
            "",
        ] {
            assert!(
                AgentBindingPolicy::new([bad], false).is_err(),
                "entry {bad:?} must be rejected"
            );
        }
        assert!(
            AgentBindingPolicy::new(Vec::<String>::new(), true).is_err(),
            "auto-registration needs an allowlist"
        );
        let policy = AgentBindingPolicy::new(["operator:alice"], false).unwrap();
        assert!(policy.permits(&principal_of("operator", "alice")));
        assert!(
            !policy.permits(&principal_of("user", "alice")),
            "kind must match"
        );
        assert!(!policy.permits(&principal_of("sandbox", "alice")));
        assert!(!policy.permits(&principal_of("anonymous", "")));
        assert!(!policy.permits(&principal_of("operator", "")));
        assert!(!policy.permits(&HashMap::new()));
        assert!(!AgentBindingPolicy::default().is_enabled());
    }

    #[tokio::test]
    async fn agent_binding_refuses_creating_principals_that_are_not_allowlisted() {
        let (service, store, token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service =
            service.with_agent_binding(AgentBindingPolicy::new(["operator:alice"], true).unwrap());
        let annotations = json!({ AGENT_ID_ANNOTATION: "prod-agent" });

        for (index, caller) in [
            principal_of("user", "bob"),
            principal_of("operator", "mallory"),
            principal_of("user", "alice"),
            principal_of("sandbox", "alice"),
            principal_of("anonymous", ""),
            principal_of("unknown", ""),
            HashMap::new(),
        ]
        .into_iter()
        .enumerate()
        {
            let result = create_with_annotations(
                &service,
                &token,
                caller.clone(),
                &format!("sb-refused-{index}"),
                annotations.clone(),
            )
            .await;
            assert!(result.allowed, "POST_COMMIT never blocks a created sandbox");
            assert_eq!(
                binding_outcome(&result),
                Some("refused_principal"),
                "{caller:?}"
            );
            assert!(!result.log_annotations.contains_key("agent_id"));
        }
        assert!(
            store
                .operator_agent_detail("prod-agent", 1)
                .unwrap()
                .is_none(),
            "a refused creator must not even register the agent"
        );

        let allowed = create_with_annotations(
            &service,
            &token,
            principal_of("operator", "alice"),
            "sb-ok",
            annotations,
        )
        .await;
        assert_eq!(
            allowed.log_annotations.get("agent_id").map(String::as_str),
            Some("prod-agent")
        );
        assert!(
            store
                .operator_agent_detail("prod-agent", 1)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn agent_binding_is_off_by_default_even_for_operators() {
        let (service, store, token) = setup_service_with_jwt();
        provision_baseline(&store);
        let result = create_with_annotations(
            &service,
            &token,
            principal_of("operator", "alice"),
            "sb-default-off",
            json!({ AGENT_ID_ANNOTATION: "prod-agent" }),
        )
        .await;
        assert_eq!(binding_outcome(&result), Some("refused_principal"));
        assert!(
            store
                .operator_agent_detail("prod-agent", 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn validate_rejects_binding_annotations_from_principals_that_are_not_allowlisted() {
        let (service, _store, _token) = setup_service_with_jwt();
        let service =
            service.with_agent_binding(AgentBindingPolicy::new(["operator:alice"], false).unwrap());
        let with_annotation = json!({
            "name": "sb-x",
            "metadata": { "annotations": { AGENT_ID_ANNOTATION: "prod-agent" } }
        });
        let only_run = json!({ "labels": { RUN_ID_ANNOTATION: "run-1" } });
        let plain = json!({ "name": "sb-x", "metadata": { "annotations": { "team": "red" } } });

        for operation in [&with_annotation, &only_run] {
            assert!(
                !service
                    .evaluate_validate(
                        "CreateSandbox",
                        operation,
                        None,
                        &principal_of("user", "bob")
                    )
                    .unwrap()
                    .allowed
            );
            assert!(
                service
                    .evaluate_validate(
                        "CreateSandbox",
                        operation,
                        None,
                        &principal_of("operator", "alice")
                    )
                    .unwrap()
                    .allowed
            );
        }
        assert!(
            service
                .evaluate_validate("CreateSandbox", &plain, None, &principal_of("user", "bob"))
                .unwrap()
                .allowed,
            "creating a sandbox without binding annotations is unaffected"
        );
    }

    #[tokio::test]
    async fn agent_binding_registers_unknown_agents_only_when_enabled() {
        let (service, store, token) = setup_service_with_jwt();
        provision_baseline(&store);
        let strict = service
            .clone()
            .with_agent_binding(AgentBindingPolicy::new(["operator:alice"], false).unwrap());
        let annotations = json!({ AGENT_ID_ANNOTATION: "new-agent" });

        let refused = create_with_annotations(
            &strict,
            &token,
            principal_of("operator", "alice"),
            "sb-unknown-1",
            annotations.clone(),
        )
        .await;
        assert_eq!(binding_outcome(&refused), Some("refused"));
        assert!(
            refused.log_annotations["agent_binding_reason"].contains("not registered"),
            "{:?}",
            refused.log_annotations
        );
        assert!(
            store
                .operator_agent_detail("new-agent", 1)
                .unwrap()
                .is_none()
        );

        store
            .register_agent("new-agent", "Registered by an operator")
            .unwrap();
        let bound = create_with_annotations(
            &strict,
            &token,
            principal_of("operator", "alice"),
            "sb-unknown-2",
            annotations,
        )
        .await;
        assert_eq!(
            bound.log_annotations.get("agent_id").map(String::as_str),
            Some("new-agent")
        );

        let lenient =
            service.with_agent_binding(AgentBindingPolicy::new(["operator:alice"], true).unwrap());
        let created = create_with_annotations(
            &lenient,
            &token,
            principal_of("operator", "alice"),
            "sb-unknown-3",
            json!({ AGENT_ID_ANNOTATION: "brand-new-agent" }),
        )
        .await;
        assert_eq!(
            created.log_annotations.get("agent_id").map(String::as_str),
            Some("brand-new-agent")
        );
        assert!(
            store
                .operator_agent_detail("brand-new-agent", 1)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn agent_binding_cannot_attach_a_sandbox_to_another_agents_run() {
        let (service, store, token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service =
            service.with_agent_binding(AgentBindingPolicy::new(["operator:alice"], true).unwrap());
        store.register_agent("agent-a", "A").unwrap();
        store.register_agent("agent-b", "B").unwrap();
        store
            .create_agent_run(
                "agent-b",
                "run-b",
                "rev-1",
                TEST_TASK_PROFILE,
                EnforcementMode::Enforce,
            )
            .unwrap();
        let bound_sandboxes = |agent: &str| -> usize {
            store.operator_agent_detail(agent, 1).unwrap().unwrap()["runs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|run| run["sandboxes"].as_array().unwrap().len())
                .sum()
        };

        let other_agent = create_with_annotations(
            &service,
            &token,
            principal_of("operator", "alice"),
            "sb-steal-1",
            json!({ AGENT_ID_ANNOTATION: "agent-a", AGENT_REVISION_ANNOTATION: "rev-1", RUN_ID_ANNOTATION: "run-b" }),
        )
        .await;
        assert_eq!(binding_outcome(&other_agent), Some("refused"));
        assert!(other_agent.log_annotations["agent_binding_reason"].contains("different workload"));

        let other_revision = create_with_annotations(
            &service,
            &token,
            principal_of("operator", "alice"),
            "sb-steal-2",
            json!({ AGENT_ID_ANNOTATION: "agent-b", AGENT_REVISION_ANNOTATION: "rev-2", RUN_ID_ANNOTATION: "run-b" }),
        )
        .await;
        assert_eq!(binding_outcome(&other_revision), Some("refused"));
        assert_eq!(bound_sandboxes("agent-b"), 0, "run-b must stay untouched");

        let owner = create_with_annotations(
            &service,
            &token,
            principal_of("operator", "alice"),
            "sb-owner",
            json!({ AGENT_ID_ANNOTATION: "agent-b", AGENT_REVISION_ANNOTATION: "rev-1", RUN_ID_ANNOTATION: "run-b" }),
        )
        .await;
        assert_eq!(
            owner.log_annotations.get("run_id").map(String::as_str),
            Some("run-b")
        );
        assert_eq!(bound_sandboxes("agent-b"), 1);
    }

    #[tokio::test]
    async fn agent_binding_ignores_keys_outside_the_openshell_namespace() {
        let (service, store, token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service =
            service.with_agent_binding(AgentBindingPolicy::new(["operator:alice"], true).unwrap());
        let result = create_with_annotations(
            &service,
            &token,
            principal_of("operator", "alice"),
            "sb-bare-keys",
            json!({ "agent_id": "prod-agent", "agent-id": "prod-agent", "agentId": "prod-agent", "run_id": "run-x" }),
        )
        .await;
        assert!(
            binding_outcome(&result).is_none(),
            "no binding was attempted"
        );
        assert!(!result.log_annotations.contains_key("agent_id"));
        assert!(
            store
                .operator_agent_detail("prod-agent", 1)
                .unwrap()
                .is_none()
        );

        assert!(
            extract_agent_id(&json!({
                "agent_id": "x", "sandbox": { "agent_id": "y" }, "spec": { "agent-id": "z" }
            }))
            .is_none()
        );
        assert_eq!(
            extract_agent_id(&json!({ "metadata": { "labels": { AGENT_ID_ANNOTATION: " ok " } } }))
                .as_deref(),
            Some("ok")
        );
        assert!(!binding_annotations_present(
            &json!({ "annotations": { "agent_id": "x" } })
        ));
    }

    #[tokio::test]
    async fn post_commit_create_sandbox_with_agent_annotation_auto_binds_and_stop_delete_closes_lifecycle()
     {
        let (service, store, token) = setup_service_with_jwt();
        let service =
            service.with_agent_binding(AgentBindingPolicy::new(["operator:alice"], true).unwrap());
        let mut baseline = crate::fixture::build_standard_corpus().default_baseline;
        baseline.task_profile = TEST_TASK_PROFILE.to_string();
        store
            .store_baseline(&baseline)
            .expect("provision test baseline");

        let sandbox_id = "sb-prod-lifecycle-01";
        let committed_create = json_to_struct(&json!({
            "sandbox": {
                "metadata": {
                    "workspace": "default",
                    "id": sandbox_id,
                    "name": sandbox_id,
                    "annotations": {
                        "openshell.nvidia.com/agent-id": "prod-agent"
                    }
                }
            }
        }))
        .expect("valid struct");

        let create_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "post-commit-create-sandbox".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "CreateSandbox".to_string(),
            principal: principal_of("operator", "alice"),
            phase: Some(interceptor_evaluation::Phase::PostCommit(
                PostCommitEvaluation {
                    committed_response: Some(committed_create),
                },
            )),
        };

        let create_res = service
            .evaluate(authenticated_request(create_eval, &token))
            .await
            .expect("post_commit CreateSandbox should succeed")
            .into_inner();
        assert!(create_res.allowed);
        assert_eq!(
            create_res
                .log_annotations
                .get("agent_id")
                .map(String::as_str),
            Some("prod-agent")
        );
        let expected_run_id = format!("run-{sandbox_id}");
        assert_eq!(
            create_res.log_annotations.get("run_id").map(String::as_str),
            Some(expected_run_id.as_str())
        );

        let agent_detail = store
            .operator_agent_detail("prod-agent", 60_000)
            .expect("query agent detail")
            .expect("prod-agent should be registered");
        assert_eq!(agent_detail["agent"]["agent_id"], "prod-agent");
        let runs = agent_detail["runs"]
            .as_array()
            .expect("runs array should exist");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["run_id"], expected_run_id);
        assert!(runs[0]["ended_at_ms"].is_null());
        assert_eq!(runs[0]["sandboxes"][0]["sandbox_id"], sandbox_id);
        assert_eq!(runs[0]["sandboxes"][0]["active"], true);

        let committed_stop = json_to_struct(&json!({
            "sandbox_id": sandbox_id
        }))
        .expect("valid struct");
        let stop_eval = InterceptorEvaluation {
            interceptor_name: "risk-guard-governance".to_string(),
            binding_id: "post-commit-stop-sandbox".to_string(),
            service: OPENSHELL_SERVICE.to_string(),
            method: "StopSandbox".to_string(),
            principal: HashMap::new(),
            phase: Some(interceptor_evaluation::Phase::PostCommit(
                PostCommitEvaluation {
                    committed_response: Some(committed_stop),
                },
            )),
        };

        let stop_res = service
            .evaluate(authenticated_request(stop_eval, &token))
            .await
            .expect("post_commit StopSandbox should succeed")
            .into_inner();
        assert!(stop_res.allowed);
        assert_eq!(
            stop_res
                .log_annotations
                .get("sandbox_id")
                .map(String::as_str),
            Some(sandbox_id)
        );
        assert_eq!(
            stop_res
                .log_annotations
                .get("ended_run_id")
                .map(String::as_str),
            Some(expected_run_id.as_str())
        );
        assert!(
            store
                .get_active_epoch(sandbox_id)
                .expect("query active epoch")
                .is_none()
        );

        let after_stop = store
            .operator_agent_detail("prod-agent", 60_000)
            .expect("query agent detail after stop")
            .expect("prod-agent should exist");
        let after_runs = after_stop["runs"].as_array().unwrap();
        assert!(after_runs[0]["ended_at_ms"].is_number());
        assert_eq!(after_runs[0]["sandboxes"][0]["active"], false);

        // Also verify DeleteSandbox POST_COMMIT terminates epoch and ends bound run.
        let sandbox_id_2 = "sb-prod-lifecycle-02";
        service
            .post_commit_sandbox_mutation(
                "CreateSandbox",
                &json!({
                    "sandbox": {
                        "metadata": {
                            "workspace": "default",
                            "id": sandbox_id_2,
                            "annotations": {
                                "openshell.nvidia.com/agent-id": "prod-agent",
                                "openshell.nvidia.com/run-id": "run-delete-test"
                            }
                        }
                    }
                }),
                &principal_of("operator", "alice"),
            )
            .expect("create second sandbox");
        assert!(store.get_active_epoch(sandbox_id_2).unwrap().is_some());

        let delete_res = service
            .evaluate_post_commit(
                "DeleteSandbox",
                &json!({"name": sandbox_id_2}),
                &HashMap::new(),
            )
            .expect("DeleteSandbox post_commit");
        assert!(delete_res.allowed);
        assert_eq!(
            delete_res
                .log_annotations
                .get("ended_run_id")
                .map(String::as_str),
            Some("run-delete-test")
        );
        assert!(store.get_active_epoch(sandbox_id_2).unwrap().is_none());
    }

    fn derive_service(base: &RiskGuardInterceptorService) -> RiskGuardInterceptorService {
        base.clone().with_agent_binding(
            AgentBindingPolicy::new(Vec::<String>::new(), false)
                .unwrap()
                .with_principal_derivation(true),
        )
    }

    fn create_in_workspace(
        service: &RiskGuardInterceptorService,
        principal: HashMap<String, String>,
        sandbox_id: &str,
        workspace: &str,
        annotations: Value,
    ) -> InterceptorResult {
        service
            .post_commit_sandbox_mutation(
                "CreateSandbox",
                &json!({
                    "sandbox": {
                        "metadata": {
                            "id": sandbox_id,
                            "workspace": workspace,
                            "annotations": annotations
                        }
                    }
                }),
                &principal,
            )
            .expect("create sandbox")
    }

    fn bound_workload(result: &InterceptorResult) -> Option<&str> {
        result.log_annotations.get("agent_id").map(String::as_str)
    }

    #[test]
    fn principal_derivation_binds_an_unlabeled_sandbox_to_its_workspace_and_principal() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);

        let created = create_in_workspace(
            &service,
            principal_of("user", "alice@example.com"),
            "sb-derive-1",
            "team-a",
            json!({}),
        );
        let workload = bound_workload(&created)
            .expect("bound to a derived workload")
            .to_string();
        assert!(
            workload.starts_with("team-a.user.alice-example-com-"),
            "{workload}"
        );
        assert_eq!(
            created
                .log_annotations
                .get("agent_binding_source")
                .map(String::as_str),
            Some("principal")
        );
        assert_eq!(
            created.log_annotations.get("workspace").map(String::as_str),
            Some("team-a")
        );
        assert!(
            store.operator_agent_detail(&workload, 1).unwrap().is_some(),
            "auto-registered"
        );

        let audit = store.list_binding_audit("sb-derive-1").unwrap();
        assert_eq!(audit.len(), 1);
        assert!(audit[0].bound);
        assert_eq!(audit[0].source, "principal");
        assert_eq!(audit[0].principal_subject, "alice@example.com");
        assert_eq!(audit[0].workspace, "team-a");

        // The console reads the same facts through the operator API.
        let detail = store.operator_agent_detail(&workload, 1).unwrap().unwrap();
        let binding = &detail["runs"][0]["sandboxes"][0]["binding"];
        assert_eq!(binding["workspace"], "team-a");
        assert_eq!(binding["principal_kind"], "user");
        assert_eq!(binding["principal_subject"], "alice@example.com");
        assert_eq!(binding["source"], "principal");
    }

    #[test]
    fn explicitly_bound_sandboxes_report_no_creating_principal() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        store.register_agent("explicit-agent", "Explicit").unwrap();
        // No derivation and no label: the sandbox is bound later with run-bind semantics.
        let created = create_in_workspace(
            &service,
            principal_of("user", "alice"),
            "sb-explicit-1",
            "default",
            json!({}),
        );
        assert!(bound_workload(&created).is_none());
        store
            .create_agent_run(
                "explicit-agent",
                "run-explicit",
                "v1",
                TEST_TASK_PROFILE,
                EnforcementMode::Enforce,
            )
            .unwrap();
        store
            .bind_agent_run("run-explicit", "sb-explicit-1", TEST_GATEWAY_ID)
            .unwrap();
        let detail = store
            .operator_agent_detail("explicit-agent", 1)
            .unwrap()
            .unwrap();
        assert!(detail["runs"][0]["sandboxes"][0]["binding"].is_null());
    }

    #[test]
    fn the_same_workspace_and_principal_share_one_workload_across_sandboxes() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);
        let alice = || principal_of("user", "alice");

        let first = create_in_workspace(&service, alice(), "sb-same-1", "team-a", json!({}));
        let second = create_in_workspace(&service, alice(), "sb-same-2", "team-a", json!({}));
        assert!(bound_workload(&first).is_some());
        assert_eq!(bound_workload(&first), bound_workload(&second));
    }

    #[test]
    fn a_different_principal_or_workspace_gets_a_different_workload() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);

        let base = create_in_workspace(
            &service,
            principal_of("user", "alice"),
            "sb-diff-1",
            "team-a",
            json!({}),
        );
        let other_principal = create_in_workspace(
            &service,
            principal_of("user", "bob"),
            "sb-diff-2",
            "team-a",
            json!({}),
        );
        let other_workspace = create_in_workspace(
            &service,
            principal_of("user", "alice"),
            "sb-diff-3",
            "team-b",
            json!({}),
        );
        assert_ne!(bound_workload(&base), bound_workload(&other_principal));
        assert_ne!(
            bound_workload(&base),
            bound_workload(&other_workspace),
            "workspace must scope the workload"
        );
    }

    #[test]
    fn a_sandbox_that_reports_no_workspace_is_refused_not_assumed() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);

        let created = create_in_workspace(
            &service,
            principal_of("user", "alice"),
            "sb-ws-1",
            "",
            json!({}),
        );
        assert_eq!(binding_outcome(&created), Some("refused"));
        assert!(created.log_annotations["agent_binding_reason"].contains("no workspace"));
        assert!(bound_workload(&created).is_none());
        let audit = store.list_binding_audit("sb-ws-1").unwrap();
        assert_eq!(audit.len(), 1);
        assert!(!audit[0].bound);
    }

    #[test]
    fn callers_without_a_durable_identity_stay_unbound_and_are_audited() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);

        for (i, principal) in [
            principal_of("anonymous", ""),
            principal_of("sandbox", "sb-x"),
            HashMap::new(),
        ]
        .into_iter()
        .enumerate()
        {
            let sandbox = format!("sb-anon-{i}");
            let created = create_in_workspace(&service, principal, &sandbox, "default", json!({}));
            assert_eq!(
                binding_outcome(&created),
                Some("refused"),
                "{:?}",
                created.log_annotations
            );
            assert!(bound_workload(&created).is_none());
            let audit = store.list_binding_audit(&sandbox).unwrap();
            assert_eq!(audit.len(), 1);
            assert!(!audit[0].bound);
            assert!(audit[0].reason.is_some());
        }
    }

    #[test]
    fn derivation_is_off_unless_enabled() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let created = create_in_workspace(
            &service,
            principal_of("user", "alice"),
            "sb-off-1",
            "default",
            json!({}),
        );
        assert!(bound_workload(&created).is_none());
        assert!(binding_outcome(&created).is_none());
        assert!(store.list_binding_audit("sb-off-1").unwrap().is_empty());
    }

    #[test]
    fn an_explicit_label_still_needs_an_allowlisted_principal_even_with_derivation_on() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);

        let refused = create_in_workspace(
            &service,
            principal_of("user", "mallory"),
            "sb-label-1",
            "team-a",
            json!({ AGENT_ID_ANNOTATION: "someone-elses-agent" }),
        );
        assert_eq!(binding_outcome(&refused), Some("refused_principal"));
        assert!(
            bound_workload(&refused).is_none(),
            "derivation must not rescue a refused label"
        );
        let audit = store.list_binding_audit("sb-label-1").unwrap();
        assert_eq!(audit[0].source, "label");
        assert!(!audit[0].bound);
    }

    #[test]
    fn a_derived_sandbox_cannot_join_a_run_owned_by_another_workload() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);

        let alice = create_in_workspace(
            &service,
            principal_of("user", "alice"),
            "sb-run-1",
            "team-a",
            json!({ RUN_ID_ANNOTATION: "shared-run" }),
        );
        assert!(bound_workload(&alice).is_some());
        let bob = create_in_workspace(
            &service,
            principal_of("user", "bob"),
            "sb-run-2",
            "team-a",
            json!({ RUN_ID_ANNOTATION: "shared-run" }),
        );
        assert_eq!(binding_outcome(&bob), Some("refused"));
        assert!(bob.log_annotations["agent_binding_reason"].contains("different workload"));
    }

    fn label_service(
        base: &RiskGuardInterceptorService,
        auto_register: bool,
    ) -> RiskGuardInterceptorService {
        base.clone().with_agent_binding(
            AgentBindingPolicy::new(["operator:alice"], auto_register)
                .unwrap()
                .with_principal_derivation(true),
        )
    }

    #[test]
    fn a_workload_scoped_to_one_workspace_refuses_binds_from_another() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        store
            .register_agent_in_workspace("team-a-agent", "Team A agent", "team-a")
            .unwrap();
        let service = label_service(&service, false);
        let label = json!({ AGENT_ID_ANNOTATION: "team-a-agent" });
        let alice = || principal_of("operator", "alice");

        let elsewhere =
            create_in_workspace(&service, alice(), "sb-scope-1", "team-b", label.clone());
        assert_eq!(binding_outcome(&elsewhere), Some("refused"));
        assert!(
            elsewhere.log_annotations["agent_binding_reason"]
                .contains("belongs to workspace 'team-a'"),
            "{:?}",
            elsewhere.log_annotations
        );
        let audit = store.list_binding_audit("sb-scope-1").unwrap();
        assert!(!audit[0].bound);

        let home = create_in_workspace(&service, alice(), "sb-scope-2", "team-a", label);
        assert_eq!(bound_workload(&home), Some("team-a-agent"));
    }

    #[test]
    fn an_unscoped_operator_workload_can_be_used_from_any_workspace() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        store.register_agent("shared-agent", "Shared").unwrap();
        let service = label_service(&service, false);
        let label = json!({ AGENT_ID_ANNOTATION: "shared-agent" });

        for (i, workspace) in ["team-a", "team-b"].into_iter().enumerate() {
            let created = create_in_workspace(
                &service,
                principal_of("operator", "alice"),
                &format!("sb-unscoped-{i}"),
                workspace,
                label.clone(),
            );
            assert_eq!(
                bound_workload(&created),
                Some("shared-agent"),
                "{workspace}"
            );
        }
    }

    #[test]
    fn an_auto_registered_label_is_scoped_to_the_workspace_that_created_it() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = label_service(&service, true);
        let label = json!({ AGENT_ID_ANNOTATION: "fresh-agent" });
        let alice = || principal_of("operator", "alice");

        let first = create_in_workspace(&service, alice(), "sb-auto-1", "team-a", label.clone());
        assert_eq!(bound_workload(&first), Some("fresh-agent"));
        let other = create_in_workspace(&service, alice(), "sb-auto-2", "team-b", label);
        assert_eq!(binding_outcome(&other), Some("refused"));
    }

    #[test]
    fn a_derived_workload_cannot_be_captured_with_a_label_from_another_workspace() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = label_service(&service, false);
        let derived = create_in_workspace(
            &service,
            principal_of("user", "carol"),
            "sb-capture-1",
            "team-a",
            json!({}),
        );
        let workload = bound_workload(&derived).expect("derived").to_string();

        // An allowlisted operator in another workspace names carol's derived workload as a label.
        let capture = create_in_workspace(
            &service,
            principal_of("operator", "alice"),
            "sb-capture-2",
            "team-b",
            json!({ AGENT_ID_ANNOTATION: workload }),
        );
        assert_eq!(binding_outcome(&capture), Some("refused"));
        assert!(bound_workload(&capture).is_none());
    }

    #[test]
    fn a_derived_workload_registered_before_scoping_existed_is_claimed_for_its_workspace() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = label_service(&service, false);
        let legacy =
            crate::workload_identity::derive_workload("team-a", "oidc", "user", "carol", false)
                .unwrap();
        store
            .register_agent(&legacy.agent_id, &legacy.display_name)
            .unwrap();

        let first = create_in_workspace(
            &service,
            principal_of("user", "carol"),
            "sb-legacy-1",
            "team-a",
            json!({}),
        );
        assert_eq!(bound_workload(&first), Some(legacy.agent_id.as_str()));
        let capture = create_in_workspace(
            &service,
            principal_of("operator", "alice"),
            "sb-legacy-2",
            "team-b",
            json!({ AGENT_ID_ANNOTATION: legacy.agent_id }),
        );
        assert_eq!(binding_outcome(&capture), Some("refused"));
    }

    #[test]
    fn binding_attempts_are_counted_by_source_and_outcome() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = label_service(&service, false);
        create_in_workspace(
            &service,
            principal_of("user", "carol"),
            "sb-metric-1",
            "team-a",
            json!({}),
        );
        create_in_workspace(
            &service,
            principal_of("anonymous", ""),
            "sb-metric-2",
            "team-a",
            json!({}),
        );
        create_in_workspace(
            &service,
            principal_of("user", "mallory"),
            "sb-metric-3",
            "team-a",
            json!({ AGENT_ID_ANNOTATION: "x" }),
        );

        let metrics = store.prometheus_metrics(0).unwrap();
        assert!(
            metrics.contains(r#"workload_bindings_total{source="principal",outcome="bound"} 1"#),
            "{metrics}"
        );
        assert!(
            metrics.contains(r#"workload_bindings_total{source="principal",outcome="refused"} 1"#),
            "{metrics}"
        );
        assert!(
            metrics.contains(r#"workload_bindings_total{source="label",outcome="refused"} 1"#),
            "{metrics}"
        );
        assert!(
            metrics.contains(r#"workload_bindings_total{source="label",outcome="bound"} 0"#),
            "{metrics}"
        );
    }

    fn principal_from(provider: &str, kind: &str, subject: &str) -> HashMap<String, String> {
        let mut map = principal_of(kind, subject);
        map.insert("provider".to_string(), provider.to_string());
        map
    }

    #[test]
    fn the_same_subject_from_two_identity_providers_is_two_workloads() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);

        let oidc = create_in_workspace(
            &service,
            principal_from("oidc", "user", "alice"),
            "sb-prov-1",
            "team-a",
            json!({}),
        );
        let cloudflare = create_in_workspace(
            &service,
            principal_from("cloudflare_access", "user", "alice"),
            "sb-prov-2",
            "team-a",
            json!({}),
        );
        assert!(bound_workload(&oidc).is_some());
        assert_ne!(bound_workload(&oidc), bound_workload(&cloudflare));
        assert_eq!(
            store.list_binding_audit("sb-prov-2").unwrap()[0].principal_provider,
            "cloudflare_access"
        );
    }

    #[test]
    fn the_unauthenticated_local_dev_user_does_not_own_a_workload_unless_allowed() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let local = || principal_from("local_dev", "user", "unauthenticated-local-dev");

        let strict = derive_service(&service);
        let refused = create_in_workspace(&strict, local(), "sb-dev-1", "default", json!({}));
        assert_eq!(binding_outcome(&refused), Some("refused"));
        assert!(
            refused.log_annotations["agent_binding_reason"].contains("--allow-local-dev-principal")
        );

        let lenient = service.clone().with_agent_binding(
            AgentBindingPolicy::new(Vec::<String>::new(), false)
                .unwrap()
                .with_principal_derivation(true)
                .with_local_dev_principals(true),
        );
        let allowed = create_in_workspace(&lenient, local(), "sb-dev-2", "default", json!({}));
        assert!(bound_workload(&allowed).is_some());
    }

    #[test]
    fn a_principal_with_no_recognized_provider_cannot_own_a_workload() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);
        let mut no_provider = principal_of("user", "alice");
        no_provider.remove("provider");
        let created =
            create_in_workspace(&service, no_provider, "sb-noprov-1", "default", json!({}));
        assert_eq!(binding_outcome(&created), Some("refused"));
    }

    #[test]
    fn the_label_allowlist_does_not_trust_the_unauthenticated_local_dev_user() {
        let policy = AgentBindingPolicy::new(["user:unauthenticated-local-dev"], false).unwrap();
        assert!(!policy.permits(&principal_from(
            "local_dev",
            "user",
            "unauthenticated-local-dev"
        )));
        assert!(
            policy
                .with_local_dev_principals(true)
                .permits(&principal_from(
                    "local_dev",
                    "user",
                    "unauthenticated-local-dev"
                ))
        );
    }

    #[test]
    fn a_replayed_create_sandbox_does_not_repeat_the_audit_entry() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = derive_service(&service);
        for _ in 0..2 {
            create_in_workspace(
                &service,
                principal_of("user", "alice"),
                "sb-replay-1",
                "team-a",
                json!({}),
            );
        }
        assert_eq!(store.list_binding_audit("sb-replay-1").unwrap().len(), 1);
    }

    #[test]
    fn a_readable_name_is_shown_next_to_a_labeled_workload_and_upgrades_an_auto_name_once() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = label_service(&service, true);
        let alice = || principal_of("operator", "alice");
        let id = "ae709341-6fdc-47f8-a5d8-175f7401f216";
        let display = |store: &SqliteRiskStore| {
            store.operator_agent_detail(id, 1).unwrap().unwrap()["agent"]["display_name"]
                .as_str()
                .unwrap()
                .to_string()
        };

        // First sight without a name: the ID is the name.
        create_in_workspace(
            &service,
            alice(),
            "sb-name-1",
            "default",
            json!({ AGENT_ID_ANNOTATION: id }),
        );
        assert_eq!(display(&store), id);

        // A later sandbox supplies the readable name, which replaces the auto-generated one.
        create_in_workspace(
            &service,
            alice(),
            "sb-name-2",
            "default",
            json!({ AGENT_ID_ANNOTATION: id, AGENT_NAME_ANNOTATION: "openshell-agent-nat-agent" }),
        );
        assert_eq!(display(&store), "openshell-agent-nat-agent");

        // Once named, a different name from a later sandbox does not overwrite it.
        create_in_workspace(
            &service,
            alice(),
            "sb-name-3",
            "default",
            json!({ AGENT_ID_ANNOTATION: id, AGENT_NAME_ANNOTATION: "something-else" }),
        );
        assert_eq!(display(&store), "openshell-agent-nat-agent");
    }

    #[test]
    fn an_unreasonable_name_is_ignored_not_fatal() {
        let (service, store, _token) = setup_service_with_jwt();
        provision_baseline(&store);
        let service = label_service(&service, true);
        let created = create_in_workspace(
            &service,
            principal_of("operator", "alice"),
            "sb-badname-1",
            "default",
            json!({ AGENT_ID_ANNOTATION: "named-agent", AGENT_NAME_ANNOTATION: "x".repeat(300) }),
        );
        assert_eq!(bound_workload(&created), Some("named-agent"));
        let detail = store
            .operator_agent_detail("named-agent", 1)
            .unwrap()
            .unwrap();
        assert_eq!(detail["agent"]["display_name"], "named-agent");
    }

    #[test]
    fn the_cli_flag_enables_derivation_without_an_allowlist() {
        let policy = AgentBindingPolicy::new(Vec::<String>::new(), false)
            .unwrap()
            .with_principal_derivation(true);
        assert!(policy.is_enabled());
        assert!(policy.derives_from_principal());
        assert!(
            !policy.permits(&principal_of("user", "alice")),
            "labels still need the allowlist"
        );
    }
}
