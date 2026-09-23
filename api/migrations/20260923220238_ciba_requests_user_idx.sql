-- no-transaction
-- Deleting a user cascades to their CIBA requests (the pending index only
-- holds pending ones, which the foreign key check cannot rely on).
CREATE INDEX CONCURRENTLY IF NOT EXISTS ciba_requests_user_idx ON ciba_requests (tenant_id, user_id);
