-- no-transaction
-- Deleting a role cascades to its assignments; the unique keys that start
-- with `role_id` are partial (user or group principals), so neither serves it.
CREATE INDEX CONCURRENTLY IF NOT EXISTS role_assignments_role_idx ON role_assignments (tenant_id, role_id);
