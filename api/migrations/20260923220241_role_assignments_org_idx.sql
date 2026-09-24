-- no-transaction
-- An organization's role grants, in the order the admin API lists them, and
-- the cascade when the organization is deleted (the unique keys hold `org_id`
-- inside a COALESCE, which neither can use).
CREATE INDEX CONCURRENTLY IF NOT EXISTS role_assignments_org_idx
    ON role_assignments (tenant_id, org_id, created_at, id) WHERE org_id IS NOT NULL;
