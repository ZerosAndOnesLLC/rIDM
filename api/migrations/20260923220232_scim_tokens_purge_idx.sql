-- no-transaction
-- The hourly cleanup deletes expired and revoked SCIM tokens across every
-- tenant (`LEAST` ignores NULLs; a token with neither is kept).
CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_tokens_purge_idx
    ON scim_tokens (LEAST(expires_at, revoked_at));
