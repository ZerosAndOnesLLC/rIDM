-- no-transaction
-- Deleting a client cascades to its CIBA requests.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ciba_requests_client_idx ON ciba_requests (tenant_id, client_id);
