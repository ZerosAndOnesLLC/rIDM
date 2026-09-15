-- 0008: OAuth/OIDC clients, scopes, claim mappers, consents, resource servers
-- and permissions. Default scopes are seeded for every tenant (existing and
-- future) so `openid`, `profile`, ... always exist.

-- This migration touches RLS-protected rows (orphan cleanup below); the
-- bypass is transaction-local and ends with the migration.
SELECT set_config('app.bypass_rls', 'on', true);

-- ---------------------------------------------------------------------------
-- clients
-- ---------------------------------------------------------------------------
CREATE TABLE clients (
    id                              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id                       text        NOT NULL,
    name                            text        NOT NULL,
    client_type                     text        NOT NULL,
    description                     text,
    logo_uri                        text,
    client_uri                      text,
    tos_uri                         text,
    policy_uri                      text,
    -- [{"id": uuid, "hash": base64url(sha256(secret)), "created_at": ts, "expires_at": ts|null}]
    secret_hashes                   jsonb       NOT NULL DEFAULT '[]'::jsonb,
    jwks                            jsonb,
    jwks_uri                        text,
    token_endpoint_auth_method      text        NOT NULL,
    redirect_uris                   text[]      NOT NULL DEFAULT '{}',
    post_logout_redirect_uris       text[]      NOT NULL DEFAULT '{}',
    allowed_grants                  text[]      NOT NULL DEFAULT '{}',
    allowed_scopes                  text[]      NOT NULL DEFAULT '{}',
    allowed_audiences               text[]      NOT NULL DEFAULT '{}',
    access_token_ttl_secs           integer,
    refresh_token_ttl_secs          integer,
    id_token_ttl_secs               integer,
    access_token_format             text        NOT NULL DEFAULT 'jwt',
    id_token_encryption             jsonb,
    subject_type                    text        NOT NULL DEFAULT 'public',
    sector_identifier_uri           text,
    require_pkce                    boolean     NOT NULL DEFAULT true,
    require_consent                 boolean     NOT NULL DEFAULT true,
    cors_origins                    text[]      NOT NULL DEFAULT '{}',
    initiate_login_uri              text,
    backchannel_logout_uri          text,
    frontchannel_logout_uri         text,
    service_account_user_id         uuid,
    registration_access_token_hash  bytea,
    status                          text        NOT NULL DEFAULT 'active',
    created_at                      timestamptz NOT NULL DEFAULT now(),
    updated_at                      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT clients_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT clients_tenant_client_id_key UNIQUE (tenant_id, client_id),
    CONSTRAINT clients_client_id_format CHECK (client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CONSTRAINT clients_type_check CHECK (client_type IN ('spa', 'web', 'native', 'machine', 'device')),
    CONSTRAINT clients_auth_method_check CHECK (token_endpoint_auth_method IN
        ('none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt')),
    CONSTRAINT clients_token_format_check CHECK (access_token_format IN ('jwt', 'opaque')),
    CONSTRAINT clients_subject_type_check CHECK (subject_type IN ('public', 'pairwise')),
    CONSTRAINT clients_status_check CHECK (status IN ('active', 'disabled')),
    FOREIGN KEY (tenant_id, service_account_user_id) REFERENCES users(tenant_id, id) ON DELETE SET NULL
);

CREATE INDEX clients_tenant_status_idx ON clients (tenant_id, status);
CREATE INDEX clients_tenant_created_idx ON clients (tenant_id, created_at, id);
CREATE INDEX clients_tenant_type_idx ON clients (tenant_id, client_type);

CREATE TRIGGER clients_set_updated_at BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Roles may be scoped to a client; refresh tokens belong to a client.
-- Rows written before clients existed (pre-release data) cannot satisfy the
-- new constraints and are removed.
DELETE FROM refresh_tokens rt
    WHERE NOT EXISTS (SELECT 1 FROM clients c WHERE c.tenant_id = rt.tenant_id AND c.client_id = rt.client_id);
UPDATE roles SET client_id = NULL
    WHERE client_id IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM clients c WHERE c.tenant_id = roles.tenant_id AND c.id = roles.client_id);
ALTER TABLE roles
    ADD CONSTRAINT roles_client_fk FOREIGN KEY (tenant_id, client_id)
        REFERENCES clients(tenant_id, id) ON DELETE CASCADE;
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_client_fk FOREIGN KEY (tenant_id, client_id)
        REFERENCES clients(tenant_id, client_id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- resource servers and permissions
-- ---------------------------------------------------------------------------
CREATE TABLE resource_servers (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identifier             text        NOT NULL,
    name                   text        NOT NULL,
    token_ttl_secs         integer,
    signing_alg            text,
    allow_offline_access   boolean     NOT NULL DEFAULT true,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT resource_servers_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT resource_servers_tenant_identifier_key UNIQUE (tenant_id, identifier),
    CONSTRAINT resource_servers_identifier_length CHECK (length(identifier) BETWEEN 1 AND 512)
);

CREATE TRIGGER resource_servers_set_updated_at BEFORE UPDATE ON resource_servers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE permissions (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            uuid        NOT NULL,
    resource_server_id   uuid        NOT NULL,
    name                 text        NOT NULL,
    description          text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT permissions_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT permissions_tenant_rs_name_key UNIQUE (tenant_id, resource_server_id, name),
    FOREIGN KEY (tenant_id, resource_server_id) REFERENCES resource_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE permission_assignments (
    tenant_id      uuid        NOT NULL,
    role_id        uuid        NOT NULL,
    permission_id  uuid        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, role_id, permission_id),
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, permission_id) REFERENCES permissions(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX permission_assignments_permission_idx ON permission_assignments (tenant_id, permission_id);

-- ---------------------------------------------------------------------------
-- scopes
-- ---------------------------------------------------------------------------
CREATE TABLE scopes (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                 text        NOT NULL,
    description          text,
    claims               text[]      NOT NULL DEFAULT '{}',
    resource_server_id   uuid,
    -- Granted without asking on the consent screen (first-party essentials).
    is_default           boolean     NOT NULL DEFAULT false,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scopes_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT scopes_tenant_name_key UNIQUE (tenant_id, name),
    CONSTRAINT scopes_name_format CHECK (name ~ '^[\x21\x23-\x5B\x5D-\x7E]{1,128}$'),
    FOREIGN KEY (tenant_id, resource_server_id) REFERENCES resource_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE TRIGGER scopes_set_updated_at BEFORE UPDATE ON scopes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Standard OIDC scopes every tenant has. Runs with a transaction-local RLS
-- bypass that is cleared again before returning.
CREATE OR REPLACE FUNCTION seed_default_scopes(p_tenant_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    previous text := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    INSERT INTO scopes (tenant_id, name, description, claims, is_default) VALUES
        (p_tenant_id, 'openid',         'Sign you in',                       '{sub}', true),
        (p_tenant_id, 'profile',        'Your name and basic profile',       '{name,family_name,given_name,middle_name,nickname,preferred_username,profile,picture,website,gender,birthdate,zoneinfo,locale,updated_at}', false),
        (p_tenant_id, 'email',          'Your email address',                '{email,email_verified}', false),
        (p_tenant_id, 'phone',          'Your phone number',                 '{phone_number,phone_number_verified}', false),
        (p_tenant_id, 'address',        'Your postal address',               '{address}', false),
        (p_tenant_id, 'offline_access', 'Stay signed in (refresh tokens)',   '{}', false)
    ON CONFLICT (tenant_id, name) DO NOTHING;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END;
$$;

CREATE OR REPLACE FUNCTION tenants_seed_scopes_trigger() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM seed_default_scopes(NEW.id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenants_seed_default_scopes AFTER INSERT ON tenants
    FOR EACH ROW EXECUTE FUNCTION tenants_seed_scopes_trigger();

-- Backfill tenants created before this migration.
SELECT seed_default_scopes(id) FROM tenants;

-- ---------------------------------------------------------------------------
-- claim mappers
-- ---------------------------------------------------------------------------
CREATE TABLE claim_mappers (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id   uuid,       -- NULL = applies to every client of the tenant
    name        text        NOT NULL,
    -- {"type": ..., "claim": ..., ..., "include_in": ["access", "id", "userinfo"]}
    config      jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT claim_mappers_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT claim_mappers_name_length CHECK (length(name) BETWEEN 1 AND 255),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX claim_mappers_tenant_client_name_key
    ON claim_mappers (tenant_id, COALESCE(client_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
CREATE INDEX claim_mappers_tenant_client_idx ON claim_mappers (tenant_id, client_id);

CREATE TRIGGER claim_mappers_set_updated_at BEFORE UPDATE ON claim_mappers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- consents
-- ---------------------------------------------------------------------------
CREATE TABLE consents (
    tenant_id   uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    client_id   uuid        NOT NULL,
    scopes      text[]      NOT NULL DEFAULT '{}',
    granted_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    PRIMARY KEY (tenant_id, user_id, client_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX consents_client_idx ON consents (tenant_id, client_id);

-- ---------------------------------------------------------------------------
-- Row level security
-- ---------------------------------------------------------------------------
SELECT enable_tenant_rls(t) FROM unnest(ARRAY[
    'clients', 'resource_servers', 'permissions', 'permission_assignments',
    'scopes', 'claim_mappers', 'consents'
]::regclass[]) AS t;
