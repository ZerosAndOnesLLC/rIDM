-- Initial access tokens for dynamic client registration (RFC 7591 §1.2,
-- `dcr.mode = initial_access_token`). They used to live only in Valkey,
-- keyed by hash, which left an administrator no way to list or revoke them;
-- a row per token gives both, and registrations are rare enough that the
-- database is the right home for the use counter too.

CREATE TABLE dcr_initial_access_tokens (
    id           uuid        PRIMARY KEY,
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- What it is for, shown in the list
    description  text,
    -- SHA-256 of the token; the token itself is shown once
    token_hash   bytea       NOT NULL,
    -- NULL: any number of registrations
    max_uses     integer,
    uses         integer     NOT NULL DEFAULT 0,
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dcr_initial_access_tokens_tenant_hash_key UNIQUE (tenant_id, token_hash),
    CONSTRAINT dcr_initial_access_tokens_description_length CHECK (length(description) <= 200),
    CONSTRAINT dcr_initial_access_tokens_max_uses_positive CHECK (max_uses IS NULL OR max_uses > 0),
    CONSTRAINT dcr_initial_access_tokens_uses_nonnegative CHECK (uses >= 0)
);

CREATE INDEX dcr_initial_access_tokens_tenant_created_idx
    ON dcr_initial_access_tokens (tenant_id, created_at DESC, id DESC);

SELECT enable_tenant_rls('dcr_initial_access_tokens');
