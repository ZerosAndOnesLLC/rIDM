-- no-transaction
-- The hourly cleanup deletes finished deliveries across every tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS webhook_deliveries_purge_idx
    ON webhook_deliveries (created_at) WHERE status IN ('delivered', 'dead');
