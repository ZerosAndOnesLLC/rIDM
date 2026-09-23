-- no-transaction
-- Live sessions of a tenant (the dashboard's count); revoked ones stay in the
-- table until the cleanup job removes them.
CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_sessions_live_idx
    ON sso_sessions (tenant_id, expires_at) WHERE revoked_at IS NULL;
