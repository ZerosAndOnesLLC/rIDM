-- 0021: personal access tokens: long-lived bearer tokens a user mints for
-- scripts and integrations, scoped to a subset of their own permissions.

CREATE TABLE personal_access_tokens (
    id            uuid        PRIMARY KEY,
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id       uuid        NOT NULL,
    name          text        NOT NULL,
    -- SHA-256 of the token; the token itself is shown once
    token_hash    bytea       NOT NULL UNIQUE,
    -- `account` (the self-service API) and admin permission names
    scopes        text[]      NOT NULL DEFAULT '{}',
    expires_at    timestamptz,
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT personal_access_tokens_name_length CHECK (length(name) BETWEEN 1 AND 100)
);

CREATE INDEX personal_access_tokens_user_idx ON personal_access_tokens (tenant_id, user_id, created_at DESC);

SELECT enable_tenant_rls('personal_access_tokens');
