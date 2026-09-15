-- 0006: refresh tokens. Opaque, stored hashed, rotated on every use; a
-- consumed token presented again reveals theft and revokes the whole family.
-- client_id is the public client identifier string; the clients table
-- (Phase 3.1) adds a foreign key once it exists.

CREATE TABLE refresh_tokens (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    family_id    uuid        NOT NULL,
    client_id    text        NOT NULL,
    user_id      uuid,
    session_id   uuid,
    token_hash   bytea       NOT NULL,
    scopes       text[]      NOT NULL DEFAULT '{}',
    audiences    text[]      NOT NULL DEFAULT '{}',
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT refresh_tokens_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT refresh_tokens_tenant_hash_key UNIQUE (tenant_id, token_hash),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (tenant_id, family_id);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (tenant_id, user_id) WHERE user_id IS NOT NULL;
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens (tenant_id, session_id) WHERE session_id IS NOT NULL;
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (tenant_id, expires_at);

SELECT enable_tenant_rls('refresh_tokens');
