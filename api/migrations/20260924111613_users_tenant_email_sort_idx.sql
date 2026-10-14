-- no-transaction
-- Sorting users by email (Phase 15.11): the unique email index is partial and
-- excludes rows without one; the list orders every row, nulls first.
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_tenant_email_sort_idx
    ON users (tenant_id, (coalesce(email, '')), id);
