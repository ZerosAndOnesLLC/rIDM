-- no-transaction
-- The hourly cleanup deletes old device-code rows across every tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS device_codes_purge_idx ON device_codes (created_at);
