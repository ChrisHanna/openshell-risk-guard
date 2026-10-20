-- A workload ID may be scoped to one OpenShell workspace. A scoped workload can only be bound
-- from sandboxes created in that workspace, so one team cannot attach to another team's workload.
-- Workloads without a row here are unscoped: an operator registered them without a workspace.
CREATE TABLE IF NOT EXISTS agent_workspaces (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id),
    workspace TEXT NOT NULL
);
