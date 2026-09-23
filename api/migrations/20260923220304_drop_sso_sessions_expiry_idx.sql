-- no-transaction
-- Replaced by the purge and live-session indexes.
DROP INDEX CONCURRENTLY IF EXISTS sso_sessions_expiry_idx;
