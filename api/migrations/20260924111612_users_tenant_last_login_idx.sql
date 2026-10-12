-- no-transaction
-- The console sorts its users list on the server with a keyset cursor over
-- the chosen key (Phase 15.11); username, status and created_at already have
-- per-tenant indexes. Last sign-in orders nulls first through the same
-- coalesce the query uses. One statement per file: CREATE INDEX CONCURRENTLY
-- refuses an implicit transaction block.
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_tenant_last_login_idx
    ON users (tenant_id, (coalesce(last_login_at, 'epoch'::timestamptz)), id);
