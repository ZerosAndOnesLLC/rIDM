-- no-transaction
-- The admin user search's prefix match on email (see the username index).
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_email_pattern_idx
    ON users (tenant_id, email text_pattern_ops) WHERE email IS NOT NULL;
