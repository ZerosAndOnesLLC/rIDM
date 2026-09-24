-- no-transaction
-- An organization's members are listed a page at a time in the order they
-- joined; the primary key (tenant_id, org_id, user_id) cannot serve that order.
CREATE INDEX CONCURRENTLY IF NOT EXISTS organization_members_joined_idx ON organization_members (tenant_id, org_id, created_at, user_id);
