-- Agent registration and run bindings are trusted operator inputs, never workload claims.
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scoring_contexts (
    context_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    agent_revision TEXT NOT NULL,
    task_profile TEXT NOT NULL,
    baseline_hash TEXT NOT NULL REFERENCES artifacts(artifact_hash),
    detector_version TEXT NOT NULL,
    configuration_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('observe', 'enforce')),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (agent_id, agent_revision, task_profile, baseline_hash, configuration_id, mode)
);
CREATE TABLE IF NOT EXISTS agent_runs (
    run_id TEXT PRIMARY KEY,
    context_id TEXT NOT NULL REFERENCES scoring_contexts(context_id),
    created_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS epoch_bindings (
    epoch_id TEXT PRIMARY KEY REFERENCES epochs(epoch_id),
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_required_sandboxes (
    sandbox_id TEXT PRIMARY KEY,
    gateway_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decision_identity (
    epoch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES agent_runs(run_id),
    PRIMARY KEY (epoch_id, request_id),
    FOREIGN KEY (epoch_id, request_id) REFERENCES decisions(epoch_id, request_id)
);
-- epoch_id is the state-owner column for compatibility with the shared state helpers;
-- in these two tables it references a scoring context, never an execution epoch.
CREATE TABLE IF NOT EXISTS agent_window_buckets (
    epoch_id TEXT NOT NULL REFERENCES scoring_contexts(context_id),
    bucket_kind TEXT NOT NULL,
    bucket_start_ms INTEGER NOT NULL,
    req_count INTEGER NOT NULL,
    resources_json TEXT NOT NULL,
    PRIMARY KEY (epoch_id, bucket_kind, bucket_start_ms)
);
CREATE TABLE IF NOT EXISTS agent_restrictions (
    epoch_id TEXT NOT NULL REFERENCES scoring_contexts(context_id),
    scope TEXT NOT NULL,
    tier TEXT NOT NULL,
    cooldown_until_ms INTEGER NOT NULL,
    strike_count INTEGER NOT NULL,
    trigger_request_id TEXT NOT NULL,
    created_sequence INTEGER NOT NULL,
    PRIMARY KEY (epoch_id, scope)
);
CREATE TABLE IF NOT EXISTS agent_restriction_origins (
    context_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    epoch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    PRIMARY KEY (context_id, scope),
    FOREIGN KEY (context_id, scope) REFERENCES agent_restrictions(epoch_id, scope),
    FOREIGN KEY (epoch_id, request_id) REFERENCES decisions(epoch_id, request_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_contexts ON scoring_contexts(agent_id, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_agent_runs_context ON agent_runs(context_id, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_bindings_run ON epoch_bindings(run_id);
CREATE INDEX IF NOT EXISTS idx_decision_identity_run ON decision_identity(run_id);
