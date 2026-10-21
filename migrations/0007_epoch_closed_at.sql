-- When an epoch was closed (its sandbox deleted, stopped or replaced). NULL while the epoch is active and for
-- epochs closed before this column existed. Used to report real lifecycle activity instead of "not collected".
-- The column itself is added by SqliteRiskStore (ALTER TABLE has no IF NOT EXISTS); this file records the intent.
SELECT 1;
