-- no-transaction
-- The hourly cleanup deletes old login attempts across every tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS login_attempts_purge_idx ON login_attempts (created_at);
