-- no-transaction
-- Device codes are only addressed by id; the cleanup has its own index.
DROP INDEX CONCURRENTLY IF EXISTS device_codes_tenant_idx;
