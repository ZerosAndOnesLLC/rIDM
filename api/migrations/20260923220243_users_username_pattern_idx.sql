-- no-transaction
-- The admin user search is a prefix match (`LIKE 'q%'`). A plain b-tree only
-- serves that under the C collation; `text_pattern_ops` serves it under any.
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_username_pattern_idx
    ON users (tenant_id, username text_pattern_ops);
