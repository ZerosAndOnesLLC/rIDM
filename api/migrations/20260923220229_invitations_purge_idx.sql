-- no-transaction
-- The hourly cleanup deletes expired, accepted and revoked invitations across
-- every tenant (`LEAST` ignores NULLs).
CREATE INDEX CONCURRENTLY IF NOT EXISTS invitations_purge_idx
    ON invitations (LEAST(expires_at, accepted_at, revoked_at));
