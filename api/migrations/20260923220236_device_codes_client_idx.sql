-- no-transaction
-- Deleting a client cascades to its device codes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS device_codes_client_idx ON device_codes (tenant_id, client_id);
