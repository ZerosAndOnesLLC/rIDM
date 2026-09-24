-- no-transaction
-- No query filters clients by type.
DROP INDEX CONCURRENTLY IF EXISTS clients_tenant_type_idx;
