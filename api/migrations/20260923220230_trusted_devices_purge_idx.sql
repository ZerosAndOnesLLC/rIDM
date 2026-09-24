-- no-transaction
-- The hourly cleanup deletes expired and revoked trusted devices across every
-- tenant (`LEAST` ignores NULLs).
CREATE INDEX CONCURRENTLY IF NOT EXISTS trusted_devices_purge_idx
    ON trusted_devices (LEAST(expires_at, revoked_at));
