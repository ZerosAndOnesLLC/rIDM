-- no-transaction
-- Administrators list the accounts whose password hash is still in a given
-- format (`?password_algo=`), for instance the ones a move to the FIPS build
-- hasn't re-hashed yet, a page at a time in the list's own order.
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_tenant_password_algo_idx
    ON users (tenant_id, password_algo, created_at, id)
    WHERE deleted_at IS NULL AND password_algo IS NOT NULL;
