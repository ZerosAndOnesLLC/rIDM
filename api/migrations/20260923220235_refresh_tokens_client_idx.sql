-- no-transaction
-- Deleting a client cascades to its refresh tokens.
CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_tokens_client_idx ON refresh_tokens (tenant_id, client_id);
