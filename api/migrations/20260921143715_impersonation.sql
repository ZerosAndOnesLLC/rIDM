-- Admin impersonation (Phase 12.4).
--
-- An administrator holding `ridm:users:impersonate` may open a browser
-- session as one of the tenant's users, where the tenant has switched
-- impersonation on (`settings.impersonation.enabled`, off by default). The
-- session is an ordinary SSO session that also names the administrator, so
-- every token minted from it carries an `act` claim (RFC 8693 §4.1) naming
-- them, and every event recorded while it is in use names them too.
--
-- The permission goes to `ridm:owner` only: `ridm:admin` is everything except
-- tenant lifecycle and, now, this. Custom roles may be granted it.

-- Who opened the session on the user's behalf, and why. No foreign key: the
-- administrator is often a global one, whose row lives in `master`.
ALTER TABLE sso_sessions
    ADD COLUMN impersonator_id        uuid,
    ADD COLUMN impersonator_tenant_id uuid,
    ADD COLUMN impersonator_username  text,
    ADD COLUMN impersonation_reason   text;

-- A user's impersonated sessions, for the admin console and for ending them.
CREATE INDEX sso_sessions_impersonated_idx ON sso_sessions (tenant_id, user_id, created_at DESC)
    WHERE impersonator_id IS NOT NULL;

-- The acting party every token of a refresh family repeats.
ALTER TABLE refresh_tokens ADD COLUMN act jsonb;

-- The administrator behind an event recorded during an impersonated session.
-- The chain hash covers it only when it is set, so rows written before this
-- migration still verify.
ALTER TABLE audit_events ADD COLUMN impersonator_id uuid;
CREATE INDEX audit_events_tenant_impersonator_idx ON audit_events (tenant_id, impersonator_id, occurred_at)
    WHERE impersonator_id IS NOT NULL;

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
        ('ridm:users:impersonate',      'Sign in as a user to see what they see (impersonation), where the tenant allows it'),
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
        ('ridm:org-admin',      'Organization administrator: the members, roles, domains and invitations of the organizations it is granted in'),
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
              ('ridm:tenants:create', 'ridm:tenants:delete', 'ridm:tenants:import',
               'ridm:users:impersonate'))
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
        OR (r.name = 'ridm:org-admin' AND p.name IN
              ('ridm:orgs:read', 'ridm:orgs:write',
               'ridm:invitations:read', 'ridm:invitations:write',
               'ridm:roles:read'))
        OR (r.name = 'ridm:viewer' AND p.name LIKE '%:read')
     )
    ON CONFLICT DO NOTHING;

    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END;
$$;

SELECT seed_admin_model(id) FROM tenants;
