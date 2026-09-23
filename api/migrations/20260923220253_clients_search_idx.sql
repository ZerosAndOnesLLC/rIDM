-- no-transaction
-- The client list's search (`ILIKE`) on client_id and name.
CREATE INDEX CONCURRENTLY IF NOT EXISTS clients_search_idx
    ON clients USING gin (tenant_id, client_id gin_trgm_ops, name gin_trgm_ops);
