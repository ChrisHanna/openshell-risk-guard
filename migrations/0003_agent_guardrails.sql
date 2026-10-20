CREATE TABLE IF NOT EXISTS agent_guardrail_revisions (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    settings_json TEXT NOT NULL,
    settings_hash TEXT NOT NULL,
    profile_artifact_hash TEXT NOT NULL REFERENCES artifacts(artifact_hash),
    updated_by TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (agent_id, revision)
);
CREATE TABLE IF NOT EXISTS agent_guardrail_heads (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id),
    revision INTEGER NOT NULL,
    FOREIGN KEY (agent_id, revision)
        REFERENCES agent_guardrail_revisions(agent_id, revision)
);
CREATE TABLE IF NOT EXISTS decision_guardrail_revisions (
    epoch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    PRIMARY KEY (epoch_id, request_id),
    FOREIGN KEY (epoch_id, request_id) REFERENCES decisions(epoch_id, request_id),
    FOREIGN KEY (agent_id, revision)
        REFERENCES agent_guardrail_revisions(agent_id, revision)
);
