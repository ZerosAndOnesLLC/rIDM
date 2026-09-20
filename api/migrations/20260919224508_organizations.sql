-- Organizations within a tenant (Phase 12.1): a tenant's customers, business
-- units or teams, as a grouping that carries membership, org-scoped role
-- grants and email domains.
--
-- `users.org_id`, `role_assignments.org_id` and `invitations.org_id` were
-- reserved by earlier migrations and are only wired to a real table here. A
-- user may belong to several organizations (`organization_members`);
-- `users.org_id` is the user's primary one, used when nothing selects another.
-- The organization chosen while signing in is kept on the session, so one user
-- can act in different organizations in different sessions.
--
-- Nothing populates these tables on its own: a tenant with no organizations
-- behaves exactly as before, which is what keeps the previous release working.

-- Reserved columns may hold values from before this table existed; there is
-- nothing to point them at, so they start empty.
SELECT set_config('app.bypass_rls', 'on', true);

CREATE TABLE organizations (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug          text        NOT NULL,   -- stable, URL-safe, unique per tenant
    display_name  text        NOT NULL,
    description   text,
    status        text        NOT NULL DEFAULT 'active',
    attributes    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT organizations_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT organizations_tenant_slug_key UNIQUE (tenant_id, slug),
    -- Same shape as a tenant slug: a DNS label.
    CONSTRAINT organizations_slug_format
        CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT organizations_name_length CHECK (length(display_name) BETWEEN 1 AND 255),
    CONSTRAINT organizations_status_check CHECK (status IN ('active', 'disabled'))
);

CREATE INDEX organizations_tenant_created_idx ON organizations (tenant_id, created_at, id);

CREATE TRIGGER organizations_set_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Membership: a user may be in several organizations of their tenant.
CREATE TABLE organization_members (
    tenant_id   uuid        NOT NULL,
    org_id      uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, org_id, user_id),
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

-- "Which organizations is this user in?", the question the login flow asks.
CREATE INDEX organization_members_user_idx ON organization_members (tenant_id, user_id);

-- Email domains an organization claims. A verified domain with `auto_join`
-- makes every user with a verified address at that domain a member.
CREATE TABLE organization_domains (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL,
    org_id        uuid        NOT NULL,
    domain        text        NOT NULL,
    -- Proof the tenant controls the domain: published as a DNS TXT record.
    verification  text        NOT NULL,
    verified_at   timestamptz,
    auto_join     boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- One organization per domain per tenant: auto-join must have one answer.
    CONSTRAINT organization_domains_tenant_domain_key UNIQUE (tenant_id, domain),
    CONSTRAINT organization_domains_lower CHECK (domain = lower(domain)),
    CONSTRAINT organization_domains_format
        CHECK (domain ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'),
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX organization_domains_org_idx ON organization_domains (tenant_id, org_id);

CREATE TRIGGER organization_domains_set_updated_at
    BEFORE UPDATE ON organization_domains
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The reserved columns, now that there is something to reference ------------

-- A user's primary organization. Deleting the organization leaves the user.
UPDATE users SET org_id = NULL WHERE org_id IS NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id) ON DELETE SET NULL;

-- An org-scoped role grant means nothing without its organization.
UPDATE role_assignments SET org_id = NULL WHERE org_id IS NOT NULL;
ALTER TABLE role_assignments ADD CONSTRAINT role_assignments_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id) ON DELETE CASCADE;

-- An invitation outlives the organization it was for (it is also the record of
-- an acceptance), so it keeps its row and loses the organization.
UPDATE invitations SET org_id = NULL WHERE org_id IS NOT NULL;
ALTER TABLE invitations ADD CONSTRAINT invitations_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id) ON DELETE SET NULL;

-- The organization this session acts in, chosen while signing in; the source
-- of the `org_id` claim in the tokens issued through it.
ALTER TABLE sso_sessions ADD COLUMN org_id uuid;
ALTER TABLE sso_sessions ADD CONSTRAINT sso_sessions_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id) ON DELETE SET NULL;

-- Permission catalogue: ridm:orgs:read / ridm:orgs:write (user managers hold
-- both: organizations are membership, which is user management).
CREATE OR REPLACE FUNCTION seed_admin_model(p_tenant_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    previous text := current_setting('app.bypass_rls', true);
    v_rs_id  uuid;
    v_role   record;
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);

    -- Resource server ------------------------------------------------------
    INSERT INTO resource_servers (tenant_id, identifier, name, allow_offline_access, built_in)
    VALUES (p_tenant_id, 'urn:ridm:admin', 'rIDM admin API', true, true)
    ON CONFLICT (tenant_id, identifier) DO UPDATE SET built_in = true
    RETURNING id INTO v_rs_id;

    -- Permission catalogue --------------------------------------------------
    INSERT INTO permissions (tenant_id, resource_server_id, name, description)
    SELECT p_tenant_id, v_rs_id, c.name, c.description FROM (VALUES
        ('ridm:tenants:read',           'View tenant settings, branding, feature flags and IP rules'),
        ('ridm:tenants:write',          'Change tenant settings, branding, feature flags and IP rules'),
        ('ridm:tenants:create',         'Create tenants (global administrators only)'),
        ('ridm:tenants:delete',         'Delete tenants'),
        ('ridm:tenants:export',         'Export tenant configuration'),
        ('ridm:tenants:import',         'Import tenant configuration'),
        ('ridm:users:read',             'View users, their sessions, credentials, devices, tokens and consents'),
        ('ridm:users:write',            'Create, change, disable and delete users; manage their sessions, credentials, devices, tokens, consents, roles and groups'),
        ('ridm:invitations:read',       'View invitations'),
        ('ridm:invitations:write',      'Create, resend and revoke invitations; bulk import users'),
        ('ridm:groups:read',            'View groups and their members'),
        ('ridm:groups:write',           'Create, change and delete groups; manage membership'),
        ('ridm:orgs:read',              'View organizations, their members and domains'),
        ('ridm:orgs:write',             'Create, change and delete organizations; manage membership, domains and org-scoped role grants'),
        ('ridm:roles:read',             'View roles, composites and assignments'),
        ('ridm:roles:write',            'Create, change and delete roles and composites'),
        ('ridm:clients:read',           'View OAuth clients'),
        ('ridm:clients:write',          'Create, change and delete OAuth clients; generate and rotate secrets'),
        ('ridm:scopes:read',            'View scopes'),
        ('ridm:scopes:write',           'Create, change and delete scopes'),
        ('ridm:mappers:read',           'View claim mappers'),
        ('ridm:mappers:write',          'Create, change and delete claim mappers'),
        ('ridm:resource-servers:read',  'View resource servers and their permissions'),
        ('ridm:resource-servers:write', 'Create, change and delete resource servers and permissions; grant permissions to roles'),
        ('ridm:idps:read',              'View identity providers'),
        ('ridm:idps:write',             'Create, change and delete identity providers'),
        ('ridm:keys:read',              'View signing keys and master-key rotation status'),
        ('ridm:keys:write',             'Rotate and revoke signing keys'),
        ('ridm:messaging:read',         'View messaging settings and templates'),
        ('ridm:messaging:write',        'Change messaging settings and templates; send test messages'),
        ('ridm:audit:read',             'View and export the audit log'),
        ('ridm:webhooks:read',          'View webhooks and their deliveries'),
        ('ridm:webhooks:write',         'Create, change and delete webhooks; redeliver events'),
        ('ridm:scim:read',              'View SCIM provisioning tokens'),
        ('ridm:scim:write',             'Create and revoke SCIM provisioning tokens')
    ) AS c(name, description)
    ON CONFLICT (tenant_id, resource_server_id, name) DO NOTHING;

    -- Built-in roles --------------------------------------------------------
    -- `ridm:owner` may already exist in `master` from an earlier bootstrap.
    FOR v_role IN SELECT * FROM (VALUES
        ('ridm:owner',          'Owner: every admin permission, including tenant lifecycle'),
        ('ridm:admin',          'Administrator: everything except creating, deleting and importing tenants'),
        ('ridm:user-manager',   'User manager: users, invitations and groups'),
        ('ridm:client-manager', 'Client manager: clients, scopes, claim mappers and resource servers'),
        ('ridm:viewer',         'Viewer: read-only access to everything')
    ) AS r(name, description)
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM roles
             WHERE tenant_id = p_tenant_id AND client_id IS NULL AND name = v_role.name
        ) THEN
            INSERT INTO roles (tenant_id, name, description, built_in)
            VALUES (p_tenant_id, v_role.name, v_role.description, true);
        ELSE
            UPDATE roles SET built_in = true
             WHERE tenant_id = p_tenant_id AND client_id IS NULL AND name = v_role.name
               AND NOT built_in;
        END IF;
    END LOOP;

    -- Grants ----------------------------------------------------------------
    INSERT INTO permission_assignments (tenant_id, role_id, permission_id)
    SELECT p_tenant_id, r.id, p.id
      FROM roles r
      JOIN permissions p ON p.tenant_id = r.tenant_id AND p.resource_server_id = v_rs_id
     WHERE r.tenant_id = p_tenant_id AND r.client_id IS NULL AND r.built_in AND (
           (r.name = 'ridm:owner')
        OR (r.name = 'ridm:admin' AND p.name NOT IN
              ('ridm:tenants:create', 'ridm:tenants:delete', 'ridm:tenants:import'))
        OR (r.name = 'ridm:user-manager' AND p.name IN
              ('ridm:tenants:read', 'ridm:users:read', 'ridm:users:write',
               'ridm:invitations:read', 'ridm:invitations:write',
               'ridm:groups:read', 'ridm:groups:write',
               'ridm:orgs:read', 'ridm:orgs:write',
               'ridm:roles:read', 'ridm:audit:read',
               'ridm:scim:read', 'ridm:scim:write'))
        OR (r.name = 'ridm:client-manager' AND p.name IN
              ('ridm:tenants:read', 'ridm:clients:read', 'ridm:clients:write',
               'ridm:scopes:read', 'ridm:scopes:write', 'ridm:mappers:read', 'ridm:mappers:write',
               'ridm:resource-servers:read', 'ridm:resource-servers:write',
               'ridm:roles:read', 'ridm:audit:read'))
        OR (r.name = 'ridm:viewer' AND p.name LIKE '%:read')
     )
    ON CONFLICT DO NOTHING;

    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END;
$$;

SELECT seed_admin_model(id) FROM tenants;

SELECT enable_tenant_rls(t) FROM unnest(ARRAY[
    'organizations', 'organization_members', 'organization_domains'
]::regclass[]) AS t;
