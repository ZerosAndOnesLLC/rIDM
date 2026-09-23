-- no-transaction
-- The hourly cleanup deletes expired and revoked personal access tokens
-- across every tenant (`LEAST` ignores NULLs; a token with neither is kept).
CREATE INDEX CONCURRENTLY IF NOT EXISTS personal_access_tokens_purge_idx
    ON personal_access_tokens (LEAST(expires_at, revoked_at));
