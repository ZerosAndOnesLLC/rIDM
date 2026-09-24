-- no-transaction
-- The hourly cleanup deletes old CIBA requests across every tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ciba_requests_purge_idx ON ciba_requests (created_at);
