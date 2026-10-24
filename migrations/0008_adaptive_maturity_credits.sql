-- SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
-- SPDX-License-Identifier: Apache-2.0

-- What the adaptive learner actually observed, recorded when an operator credits it to a scoring context's baseline maturity.
--
-- A task profile's baseline carries two hand-kept counters (training_sessions, training_requests). A profile is "mature" only when they
-- reach 20 and 200, and until then the behavioral score records but never refuses on rarity alone. A credit lets those counters be
-- backed by real observation instead: it is written only by an explicit operator action, only for a model that passed its promotion
-- gates and is the enforced model, and it names who did it, when, which model (by hash) and what that model was trained on. It is
-- never deleted: revoking sets revoked_at_ms. It counts only while its model is still the enforced one, is not revoked, and was
-- trained under the guardrails revision now in force.
CREATE TABLE IF NOT EXISTS adaptive_maturity_credits (
    credit_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    context_id TEXT NOT NULL REFERENCES scoring_contexts(context_id),
    task_profile TEXT NOT NULL,
    model_id TEXT NOT NULL REFERENCES adaptive_models(model_id),
    model_hash TEXT NOT NULL,
    -- Independent training runs and requests the model was fitted on (the baseline's "sessions" and "requests").
    training_sessions INTEGER NOT NULL CHECK (training_sessions >= 0),
    training_requests INTEGER NOT NULL CHECK (training_requests >= 0),
    holdout_runs INTEGER NOT NULL,
    holdout_requests INTEGER NOT NULL,
    holdout_would_block INTEGER NOT NULL,
    -- How many of the model's captures a person approved, and how many the automatic clean-run policy approved.
    person_approved_sessions INTEGER NOT NULL,
    auto_approved_sessions INTEGER NOT NULL,
    granted_by TEXT NOT NULL,
    granted_at_ms INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    revoked_by TEXT,
    revoked_at_ms INTEGER,
    revoke_reason TEXT
);
-- At most one live credit per scoring context.
CREATE UNIQUE INDEX IF NOT EXISTS idx_adaptive_maturity_one_live
    ON adaptive_maturity_credits (context_id) WHERE revoked_at_ms IS NULL;
CREATE INDEX IF NOT EXISTS idx_adaptive_maturity_agent
    ON adaptive_maturity_credits (agent_id, granted_at_ms DESC);
