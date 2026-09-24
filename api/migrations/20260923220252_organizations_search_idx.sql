-- no-transaction
-- The organization list's substring search (`ILIKE '%q%'`) on slug and name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS organizations_search_idx
    ON organizations USING gin (tenant_id, slug gin_trgm_ops, display_name gin_trgm_ops);
