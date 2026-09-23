-- no-transaction
-- The hourly cleanup finds spent refresh tokens across every tenant. `LEAST`
-- ignores NULLs, so this one expression is the earliest of the three ends
-- and `LEAST(...) < cutoff` is the old three-way OR, which no index served.
CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_tokens_purge_idx
    ON refresh_tokens (LEAST(expires_at, revoked_at, consumed_at));
