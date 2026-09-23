-- no-transaction
-- CIBA requests are addressed by id or by user; the cleanup has its own index.
DROP INDEX CONCURRENTLY IF EXISTS ciba_requests_tenant_idx;
