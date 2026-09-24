-- no-transaction
-- Deleting an organization sets `org_id` to NULL on its sessions.
CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_sessions_org_idx
    ON sso_sessions (tenant_id, org_id) WHERE org_id IS NOT NULL;
