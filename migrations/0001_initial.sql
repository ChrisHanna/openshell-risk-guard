-- SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
-- SPDX-License-Identifier: Apache-2.0

-- Initial schema for openshell-risk-guard (Section 7.2 of docs/design.md).

CREATE TABLE IF NOT EXISTS epochs (
    epoch_id TEXT PRIMARY KEY,
    gateway_id TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,
    task_profile TEXT NOT NULL,
    baseline_hash TEXT NOT NULL,
    mode TEXT NOT NULL,
    active INTEGER NOT NULL,
    next_sequence INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    credentialed_endpoints_json TEXT NOT NULL,
    active_policy_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_epochs_sandbox_active
    ON epochs (sandbox_id, active, created_at_ms DESC);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_hash TEXT PRIMARY KEY,
    artifact_type TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_type_name
    ON artifacts (artifact_type, name, created_at_ms DESC);

CREATE TABLE IF NOT EXISTS decisions (
    epoch_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    sandbox_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    normalized_request_json TEXT NOT NULL,
    evaluation_json TEXT NOT NULL,
    outcome TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (epoch_id, request_id),
    FOREIGN KEY (epoch_id) REFERENCES epochs(epoch_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_epoch_sequence
    ON decisions (epoch_id, sequence);

CREATE INDEX IF NOT EXISTS idx_decisions_sandbox_sequence
    ON decisions (sandbox_id, sequence ASC, created_at_ms ASC);

CREATE TABLE IF NOT EXISTS window_buckets (
    epoch_id TEXT NOT NULL,
    bucket_kind TEXT NOT NULL,
    bucket_start_ms INTEGER NOT NULL,
    req_count INTEGER NOT NULL,
    resources_json TEXT NOT NULL,
    PRIMARY KEY (epoch_id, bucket_kind, bucket_start_ms),
    FOREIGN KEY (epoch_id) REFERENCES epochs(epoch_id)
);

CREATE INDEX IF NOT EXISTS idx_window_buckets_lookup
    ON window_buckets (epoch_id, bucket_kind, bucket_start_ms);

CREATE TABLE IF NOT EXISTS restrictions (
    epoch_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    tier TEXT NOT NULL,
    cooldown_until_ms INTEGER NOT NULL,
    strike_count INTEGER NOT NULL,
    trigger_request_id TEXT NOT NULL,
    created_sequence INTEGER NOT NULL,
    PRIMARY KEY (epoch_id, scope),
    FOREIGN KEY (epoch_id) REFERENCES epochs(epoch_id)
);

CREATE INDEX IF NOT EXISTS idx_restrictions_epoch_scope
    ON restrictions (epoch_id, scope);

CREATE TABLE IF NOT EXISTS policy_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_id TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    policy_yaml TEXT NOT NULL,
    credentialed_endpoints_json TEXT NOT NULL,
    source TEXT NOT NULL,
    captured_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_snapshots_sandbox_captured
    ON policy_snapshots (sandbox_id, captured_at_ms DESC, id DESC);

CREATE TABLE IF NOT EXISTS coverage_intervals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_id TEXT NOT NULL,
    gap_reason TEXT NOT NULL,
    start_ms INTEGER NOT NULL,
    end_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_coverage_intervals_sandbox_time
    ON coverage_intervals (sandbox_id, start_ms, end_ms);

CREATE TABLE IF NOT EXISTS recommendations (
    recommendation_id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL,
    epoch_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    FOREIGN KEY (epoch_id) REFERENCES epochs(epoch_id)
);

CREATE INDEX IF NOT EXISTS idx_recommendations_sandbox_created
    ON recommendations (sandbox_id, created_at_ms DESC);
