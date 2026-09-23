-- no-transaction
-- No query reads login attempts by identifier; every sign-in paid to write it.
DROP INDEX CONCURRENTLY IF EXISTS login_attempts_identifier_idx;
