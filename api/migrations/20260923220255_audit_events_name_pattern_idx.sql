-- The audit log's name filter matches a prefix (`name LIKE 'user.%'`), which
-- the (tenant_id, name, occurred_at) index cannot serve under the database's
-- collation; `text_pattern_ops` serves both that and the exact match.
--
-- `audit_events` is partitioned, and an index on a partitioned table cannot be
-- built CONCURRENTLY. Building it blocks inserts into the partitions for the
-- duration, and only the audit writer inserts there: it runs off the event
-- bus, outside every request, and keeps its batches until the lock goes, so
-- no request waits on this.
CREATE INDEX audit_events_tenant_name_pattern_idx
    ON audit_events (tenant_id, name text_pattern_ops, occurred_at);
DROP INDEX audit_events_tenant_name_idx;
