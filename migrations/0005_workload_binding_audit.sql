-- Who attached a sandbox to a workload, from which workspace, and how the workload was chosen.
-- Rows are appended for every attempt, including refusals, so the evidence shows
-- both what was accepted and what was turned away.
CREATE TABLE IF NOT EXISTS workload_binding_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_id TEXT NOT NULL,
    workspace TEXT NOT NULL,
    principal_kind TEXT NOT NULL,
    principal_subject TEXT NOT NULL,
    agent_id TEXT,
    source TEXT NOT NULL CHECK (source IN ('principal', 'label')),
    outcome TEXT NOT NULL CHECK (outcome IN ('bound', 'refused')),
    reason TEXT,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_binding_audit_sandbox
    ON workload_binding_audit (sandbox_id, audit_id);
