-- 0007: record which master-key generation encrypted each credential so the
-- rotation command can find rows that still need re-encryption.
ALTER TABLE credentials
    ADD COLUMN key_version integer NOT NULL DEFAULT 1;
CREATE INDEX credentials_tenant_key_version_idx ON credentials (tenant_id, key_version);
