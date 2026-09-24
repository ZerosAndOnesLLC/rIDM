-- no-transaction
-- A role's holders are listed a page at a time in grant order. Also serves
-- the cascade from a deleted role, which role_assignments_role_idx did.
CREATE INDEX CONCURRENTLY IF NOT EXISTS role_assignments_role_created_idx ON role_assignments (tenant_id, role_id, created_at, id);
