-- no-transaction
-- The delivery job's 30-second poll counts the queue and finds the tenants
-- with a message due, across every tenant. Only unsent rows are in it, so it
-- stays small however many sent messages are retained.
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbound_messages_live_idx
    ON outbound_messages (next_attempt_at, tenant_id) WHERE status IN ('queued', 'sending');
