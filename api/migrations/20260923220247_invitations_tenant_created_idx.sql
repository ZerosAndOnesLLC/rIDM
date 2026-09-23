-- no-transaction
-- The tenant-wide invitation list pages by (created_at, id).
CREATE INDEX CONCURRENTLY IF NOT EXISTS invitations_tenant_created_idx
    ON invitations (tenant_id, created_at, id);
