-- Non-secret service settings. The resource HMAC key itself is never stored; only a
-- keyed fingerprint, so a restart with a different key cannot silently split
-- rolling windows and fan-out sets.
CREATE TABLE IF NOT EXISTS service_settings (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    recorded_at_ms INTEGER NOT NULL
);

-- Append-only record of operator-cleared restrictions. Clearing removes the active
-- row so new requests are scored again; it never broadens OpenShell policy and never
-- rewrites the decisions that created the restriction.
CREATE TABLE IF NOT EXISTS restriction_clearances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('epoch', 'agent_context')),
    owner_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    tier TEXT NOT NULL,
    strike_count INTEGER NOT NULL,
    trigger_request_id TEXT NOT NULL,
    origin_epoch_id TEXT,
    origin_request_id TEXT,
    cleared_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    cleared_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_restriction_clearances_owner
    ON restriction_clearances(owner_id, id DESC);
