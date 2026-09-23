-- no-transaction
-- Replaced by the purge index; the per-tenant purge that used it is gone.
DROP INDEX CONCURRENTLY IF EXISTS refresh_tokens_expires_idx;
