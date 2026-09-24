-- no-transaction
-- Master-key rotation walks one old key generation at a time across every
-- tenant, in (tenant_id, id) order; `max(key_version)` reads its first entry.
CREATE INDEX CONCURRENTLY IF NOT EXISTS credentials_key_version_idx
    ON credentials (key_version, tenant_id, id);
