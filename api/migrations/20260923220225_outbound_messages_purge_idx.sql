-- no-transaction
-- The hourly cleanup deletes sent and dead messages across every tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbound_messages_purge_idx
    ON outbound_messages (created_at) WHERE status IN ('sent', 'dead');
