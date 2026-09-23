-- no-transaction
-- No query lists impersonated sessions apart from a user's others.
DROP INDEX CONCURRENTLY IF EXISTS sso_sessions_impersonated_idx;
