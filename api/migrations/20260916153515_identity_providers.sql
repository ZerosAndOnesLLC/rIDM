-- 0019: upstream identity providers (OIDC / OAuth 2.0 brokering) and the
-- identities users link to them.

CREATE TABLE identity_providers (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- URL-safe name used in `/broker/{alias}/...`
    alias                       text        NOT NULL,
    kind                        text        NOT NULL,
    display_name                text        NOT NULL,
    preset                      text,
    enabled                     boolean     NOT NULL DEFAULT true,
    -- not offered on the login page (reachable through a link only)
    hidden                      boolean     NOT NULL DEFAULT false,
    issuer                      text,
    authorization_endpoint      text,
    token_endpoint              text,
    userinfo_endpoint           text,
    jwks_uri                    text,
    client_id                   text        NOT NULL,
    -- encrypted under the master key; an empty secret is stored encrypted too
    client_secret_enc           bytea       NOT NULL,
    key_version                 integer     NOT NULL,
    client_secret_set           boolean     NOT NULL DEFAULT false,
    token_endpoint_auth_method  text        NOT NULL DEFAULT 'client_secret_basic',
    scopes                      text[]      NOT NULL DEFAULT '{}',
    pkce                        boolean     NOT NULL DEFAULT true,
    link_policy                 text        NOT NULL DEFAULT 'verified_email',
    -- treat the upstream email as verified even without an `email_verified` claim
    trust_email                 boolean     NOT NULL DEFAULT false,
    mappers                     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    sort_order                  integer     NOT NULL DEFAULT 0,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT identity_providers_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT identity_providers_alias_key UNIQUE (tenant_id, alias),
    CONSTRAINT identity_providers_alias_format CHECK (alias ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    CONSTRAINT identity_providers_kind_check CHECK (kind IN ('oidc', 'oauth2')),
    CONSTRAINT identity_providers_link_policy_check CHECK (link_policy IN ('verified_email', 'explicit', 'always_new')),
    CONSTRAINT identity_providers_auth_method_check CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none')),
    CONSTRAINT identity_providers_display_name_length CHECK (length(display_name) BETWEEN 1 AND 100)
);

CREATE INDEX identity_providers_tenant_idx ON identity_providers (tenant_id, sort_order, alias);

CREATE TRIGGER identity_providers_set_updated_at BEFORE UPDATE ON identity_providers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

SELECT enable_tenant_rls('identity_providers');

CREATE TABLE federated_identities (
    tenant_id          uuid        NOT NULL,
    user_id            uuid        NOT NULL,
    idp_id             uuid        NOT NULL,
    external_subject   text        NOT NULL,
    external_email     text,
    external_username  text,
    linked_at          timestamptz NOT NULL DEFAULT now(),
    last_login_at      timestamptz,
    PRIMARY KEY (tenant_id, idp_id, external_subject),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers(tenant_id, id) ON DELETE CASCADE,
    -- one identity per provider per user
    CONSTRAINT federated_identities_user_idp_key UNIQUE (tenant_id, user_id, idp_id)
);

CREATE INDEX federated_identities_user_idx ON federated_identities (tenant_id, user_id);

SELECT enable_tenant_rls('federated_identities');
