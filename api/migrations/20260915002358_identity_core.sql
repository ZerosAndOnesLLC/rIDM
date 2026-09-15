-- 0002: core identity tables — users, profile schema, password history,
-- credentials, groups, group membership, roles, role assignments, composites.
--
-- Isolation model
--   * Every table carries tenant_id; every composite index leads with it.
--   * Child rows reference parents with composite (tenant_id, id) foreign keys,
--     so a row can never point at a parent in another tenant.
--   * Row level security is ENABLED and FORCED (applies to the table owner too).
--     The API binds a tenant per transaction with
--         SELECT set_config('app.tenant_id', '<uuid>', true);
--     Explicit cross-tenant work (global admin, jobs, bootstrap) sets
--         SELECT set_config('app.bypass_rls', 'on', true);
--     and is audited. Without either, tenant-scoped tables are invisible.

CREATE OR REPLACE FUNCTION rls_bypass() RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT COALESCE(current_setting('app.bypass_rls', true), '') = 'on'
$$;

-- Apply the standard tenant isolation policy to a table.
CREATE OR REPLACE FUNCTION enable_tenant_rls(tbl regclass) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format(
        'CREATE POLICY tenant_isolation ON %s
            USING (tenant_id = current_tenant_id() OR rls_bypass())
            WITH CHECK (tenant_id = current_tenant_id() OR rls_bypass())',
        tbl);
END;
$$;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    org_id                uuid,       -- reserved for Organizations (Phase 12)
    username              text        NOT NULL,
    email                 text,
    email_verified        boolean     NOT NULL DEFAULT false,
    phone                 text,
    phone_verified        boolean     NOT NULL DEFAULT false,
    password_hash         text,
    password_algo         text,
    must_change_password  boolean     NOT NULL DEFAULT false,
    password_expires_at   timestamptz,
    password_changed_at   timestamptz,
    status                text        NOT NULL DEFAULT 'active',
    attributes            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    locale                text,
    last_login_at         timestamptz,
    failed_attempts       integer     NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    deleted_at            timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled', 'locked', 'pending', 'deleted')),
    CONSTRAINT users_username_format CHECK (username = lower(username) AND length(username) BETWEEN 1 AND 255),
    CONSTRAINT users_email_lower CHECK (email IS NULL OR email = lower(email)),
    CONSTRAINT users_password_algo_check CHECK (
        (password_hash IS NULL AND password_algo IS NULL) OR
        (password_hash IS NOT NULL AND password_algo IS NOT NULL)
    ),
    CONSTRAINT users_failed_attempts_nonneg CHECK (failed_attempts >= 0)
);

CREATE UNIQUE INDEX users_tenant_username_key ON users (tenant_id, username) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX users_tenant_email_key ON users (tenant_id, email) WHERE email IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX users_tenant_status_idx ON users (tenant_id, status);
CREATE INDEX users_tenant_created_idx ON users (tenant_id, created_at, id);
CREATE INDEX users_tenant_org_idx ON users (tenant_id, org_id) WHERE org_id IS NOT NULL;
CREATE INDEX users_tenant_deleted_idx ON users (tenant_id, deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- user_profile_schema: one document per tenant describing custom attributes
-- ---------------------------------------------------------------------------
CREATE TABLE user_profile_schema (
    tenant_id   uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    attributes  jsonb       NOT NULL DEFAULT '[]'::jsonb,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_profile_schema_is_array CHECK (jsonb_typeof(attributes) = 'array')
);

CREATE TRIGGER user_profile_schema_set_updated_at BEFORE UPDATE ON user_profile_schema
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- password_history
-- ---------------------------------------------------------------------------
CREATE TABLE password_history (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    hash        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX password_history_user_idx ON password_history (tenant_id, user_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- credentials: MFA and passwordless authenticators (secrets encrypted at rest)
-- ---------------------------------------------------------------------------
CREATE TABLE credentials (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL,
    user_id       uuid        NOT NULL,
    type          text        NOT NULL,
    data_enc      bytea       NOT NULL,
    label         text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT credentials_type_check CHECK (type IN ('password', 'totp', 'webauthn', 'recovery_code', 'email_otp', 'sms_otp'))
);

CREATE INDEX credentials_user_type_idx ON credentials (tenant_id, user_id, type);

-- ---------------------------------------------------------------------------
-- groups (nestable) and membership
-- ---------------------------------------------------------------------------
CREATE TABLE groups (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    parent_id    uuid,
    name         text        NOT NULL,
    description  text,
    attributes   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT groups_tenant_id_id_key UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, parent_id) REFERENCES groups(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT groups_name_length CHECK (length(name) BETWEEN 1 AND 255),
    CONSTRAINT groups_not_own_parent CHECK (parent_id IS DISTINCT FROM id)
);

-- Sibling names are unique; top-level groups share the nil parent slot.
CREATE UNIQUE INDEX groups_tenant_parent_name_key
    ON groups (tenant_id, COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
CREATE INDEX groups_tenant_parent_idx ON groups (tenant_id, parent_id);

CREATE TRIGGER groups_set_updated_at BEFORE UPDATE ON groups
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE group_members (
    tenant_id   uuid        NOT NULL,
    group_id    uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_id, user_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX group_members_user_idx ON group_members (tenant_id, user_id);

-- ---------------------------------------------------------------------------
-- roles, assignments, composites
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id    uuid,       -- client-scoped role; FK added with the clients table (Phase 3.1)
    name         text        NOT NULL,
    description  text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT roles_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT roles_name_length CHECK (length(name) BETWEEN 1 AND 255)
);

CREATE UNIQUE INDEX roles_tenant_client_name_key
    ON roles (tenant_id, COALESCE(client_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
CREATE INDEX roles_tenant_client_idx ON roles (tenant_id, client_id) WHERE client_id IS NOT NULL;

CREATE TRIGGER roles_set_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE role_assignments (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL,
    role_id     uuid        NOT NULL,
    user_id     uuid,
    group_id    uuid,
    org_id      uuid,       -- reserved for Organizations (Phase 12)
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT role_assignments_one_principal CHECK ((user_id IS NULL) <> (group_id IS NULL))
);

CREATE UNIQUE INDEX role_assignments_user_key
    ON role_assignments (tenant_id, role_id, user_id, COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX role_assignments_group_key
    ON role_assignments (tenant_id, role_id, group_id, COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE group_id IS NOT NULL;
CREATE INDEX role_assignments_user_idx ON role_assignments (tenant_id, user_id) WHERE user_id IS NOT NULL;
CREATE INDEX role_assignments_group_idx ON role_assignments (tenant_id, group_id) WHERE group_id IS NOT NULL;

CREATE TABLE role_composites (
    tenant_id       uuid NOT NULL,
    parent_role_id  uuid NOT NULL,
    child_role_id   uuid NOT NULL,
    PRIMARY KEY (tenant_id, parent_role_id, child_role_id),
    FOREIGN KEY (tenant_id, parent_role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, child_role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT role_composites_not_self CHECK (parent_role_id <> child_role_id)
);

CREATE INDEX role_composites_child_idx ON role_composites (tenant_id, child_role_id);

-- ---------------------------------------------------------------------------
-- Row level security
-- ---------------------------------------------------------------------------
SELECT enable_tenant_rls(t) FROM unnest(ARRAY[
    'users', 'user_profile_schema', 'password_history', 'credentials',
    'groups', 'group_members', 'roles', 'role_assignments', 'role_composites'
]::regclass[]) AS t;
