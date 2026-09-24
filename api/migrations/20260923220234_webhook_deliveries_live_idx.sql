-- no-transaction
-- The delivery job's 30-second poll counts the queue and finds the tenants
-- with a delivery due, across every tenant, `sending` included (which the
-- per-tenant due index leaves out). Only unfinished rows are in it.
CREATE INDEX CONCURRENTLY IF NOT EXISTS webhook_deliveries_live_idx
    ON webhook_deliveries (next_attempt_at, tenant_id) WHERE status IN ('pending', 'failed', 'sending');
