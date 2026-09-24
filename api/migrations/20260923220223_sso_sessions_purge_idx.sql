-- no-transaction
-- The hourly cleanup finds ended sessions across every tenant: the earliest of
-- the absolute expiry, the idle expiry and the revocation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_sessions_purge_idx
    ON sso_sessions (LEAST(expires_at, idle_expires_at, revoked_at));
