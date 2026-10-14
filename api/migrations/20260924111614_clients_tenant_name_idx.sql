-- no-transaction
-- Sorting clients by name (Phase 15.11), case-insensitively, as the list orders.
CREATE INDEX CONCURRENTLY IF NOT EXISTS clients_tenant_name_idx
    ON clients (tenant_id, lower(name), id);
