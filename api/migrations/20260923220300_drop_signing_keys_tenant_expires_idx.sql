-- no-transaction
-- No query filters signing keys by expiry.
DROP INDEX CONCURRENTLY IF EXISTS signing_keys_tenant_expires_idx;
