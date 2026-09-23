-- no-transaction
-- The console's message log lists a tenant's messages newest first.
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbound_messages_tenant_created_idx
    ON outbound_messages (tenant_id, created_at);
