-- no-transaction
-- Replaced by credentials_key_version_idx, which rotation can use.
DROP INDEX CONCURRENTLY IF EXISTS credentials_tenant_key_version_idx;
