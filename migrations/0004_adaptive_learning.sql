-- Only the authenticated supervisor RPC records this provenance. Historical and
-- direct CLI evaluations are never retroactively enrolled in a learning window.
CREATE TABLE IF NOT EXISTS native_decision_provenance (
    epoch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    auth_scope TEXT NOT NULL CHECK (auth_scope IN ('local_demo', 'verified')),
    run_id TEXT REFERENCES agent_runs(run_id),
    observed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (epoch_id, request_id),
    FOREIGN KEY (epoch_id, request_id) REFERENCES decisions(epoch_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_native_run_time
    ON native_decision_provenance(run_id, auth_scope, observed_at_ms);
CREATE TABLE IF NOT EXISTS adaptive_sessions (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    context_id TEXT NOT NULL REFERENCES scoring_contexts(context_id),
    guardrails_revision INTEGER NOT NULL CHECK (guardrails_revision >= 0),
    scope TEXT NOT NULL CHECK (scope IN ('local_demo', 'verified')),
    status TEXT NOT NULL CHECK (status IN ('recording', 'pending_review', 'approved', 'rejected', 'quarantined')),
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER,
    quarantine_reason TEXT,
    notes TEXT NOT NULL DEFAULT '',
    reviewed_by TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_adaptive_recording_run
    ON adaptive_sessions(run_id) WHERE status = 'recording';
CREATE UNIQUE INDEX IF NOT EXISTS idx_adaptive_single_capture_run ON adaptive_sessions(run_id);
CREATE INDEX IF NOT EXISTS idx_adaptive_sessions_agent
    ON adaptive_sessions(agent_id, started_at_ms DESC);
CREATE TABLE IF NOT EXISTS adaptive_observations (
    session_id TEXT NOT NULL REFERENCES adaptive_sessions(session_id),
    epoch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    base_outcome TEXT NOT NULL,
    base_risk_score INTEGER NOT NULL,
    PRIMARY KEY (epoch_id, request_id),
    FOREIGN KEY (epoch_id, request_id) REFERENCES native_decision_provenance(epoch_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_adaptive_observations_session ON adaptive_observations(session_id);
CREATE TABLE IF NOT EXISTS adaptive_models (
    model_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    context_id TEXT NOT NULL REFERENCES scoring_contexts(context_id),
    guardrails_revision INTEGER NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('local_demo', 'verified')),
    profile_json TEXT NOT NULL,
    model_hash TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    revoked_at_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_adaptive_models_agent ON adaptive_models(agent_id, created_at_ms DESC);
CREATE TABLE IF NOT EXISTS adaptive_model_sessions (
    model_id TEXT NOT NULL REFERENCES adaptive_models(model_id),
    session_id TEXT NOT NULL REFERENCES adaptive_sessions(session_id),
    split TEXT NOT NULL CHECK (split IN ('training', 'holdout')),
    PRIMARY KEY (model_id, session_id)
);
CREATE TABLE IF NOT EXISTS adaptive_heads (
    context_id TEXT NOT NULL REFERENCES scoring_contexts(context_id),
    guardrails_revision INTEGER NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('local_demo', 'verified')),
    shadow_model_id TEXT REFERENCES adaptive_models(model_id),
    enforced_model_id TEXT REFERENCES adaptive_models(model_id),
    PRIMARY KEY (context_id, guardrails_revision, scope)
);
CREATE TABLE IF NOT EXISTS adaptive_assessments (
    epoch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    model_id TEXT NOT NULL REFERENCES adaptive_models(model_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    mode TEXT NOT NULL CHECK (mode IN ('shadow', 'enforce')),
    score INTEGER NOT NULL,
    would_block INTEGER NOT NULL,
    clean_native INTEGER NOT NULL,
    assessment_json TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (epoch_id, request_id, model_id),
    FOREIGN KEY (epoch_id, request_id) REFERENCES native_decision_provenance(epoch_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_adaptive_assessments_model ON adaptive_assessments(model_id, observed_at_ms DESC);
CREATE TABLE IF NOT EXISTS adaptive_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    operation TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    details_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_adaptive_audit_agent ON adaptive_audit(agent_id, id DESC);
CREATE TABLE IF NOT EXISTS adaptive_agent_settings (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id),
    auto_shadow_learning INTEGER NOT NULL DEFAULT 1 CHECK (auto_shadow_learning IN (0, 1)),
    updated_at_ms INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);

