-- no-transaction
-- Sorting clients by type (Phase 15.11).
CREATE INDEX CONCURRENTLY IF NOT EXISTS clients_tenant_type_idx
    ON clients (tenant_id, client_type, id);
