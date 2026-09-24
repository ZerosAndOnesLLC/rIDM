-- no-transaction
-- The tenant list's search (`ILIKE`) on slug and name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS tenants_search_idx
    ON tenants USING gin (slug gin_trgm_ops, display_name gin_trgm_ops);
