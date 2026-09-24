-- no-transaction
-- Deleting an organization sets `org_id` to NULL on its refresh tokens.
CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_tokens_org_idx
    ON refresh_tokens (tenant_id, org_id) WHERE org_id IS NOT NULL;
