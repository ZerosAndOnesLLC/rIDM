-- 0013: Postgres mirror of browser SSO sessions (listing, revocation, audit;
-- Redis stays the fast path) and trusted devices for "remember me".

CREATE TABLE sso_sessions (
    id               uuid        PRIMARY KEY,
    tenant_id        uuid        NOT NULL,
    user_id          uuid        NOT NULL,
    auth_time        timestamptz NOT NULL,
    amr              text[]      NOT NULL DEFAULT '{}',
    acr              text,
    ip               text,
    user_agent       text,
    device_id        uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    idle_expires_at  timestamptz NOT NULL,
    revoked_at       timestamptz,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX sso_sessions_user_idx ON sso_sessions (tenant_id, user_id, created_at DESC);
CREATE INDEX sso_sessions_expiry_idx ON sso_sessions (tenant_id, expires_at);

CREATE TABLE trusted_devices (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL,
    user_id       uuid        NOT NULL,
    device_hash   bytea       NOT NULL,
    name          text,
    user_agent    text,
    ip            text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    CONSTRAINT trusted_devices_tenant_hash_key UNIQUE (tenant_id, device_hash),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX trusted_devices_user_idx ON trusted_devices (tenant_id, user_id, created_at DESC);

SELECT enable_tenant_rls('sso_sessions');
SELECT enable_tenant_rls('trusted_devices');
