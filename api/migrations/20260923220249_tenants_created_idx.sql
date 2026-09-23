-- no-transaction
-- The tenant list pages by (created_at, id).
CREATE INDEX CONCURRENTLY IF NOT EXISTS tenants_created_idx ON tenants (created_at, id);
