-- no-transaction
-- A group's members are listed a page at a time in the order they joined;
-- the primary key (tenant_id, group_id, user_id) cannot serve that order.
CREATE INDEX CONCURRENTLY IF NOT EXISTS group_members_joined_idx ON group_members (tenant_id, group_id, created_at, user_id);
