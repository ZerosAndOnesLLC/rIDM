-- Phase 13.3: LDAP / Active Directory upstream. A directory is an
-- `identity_providers` row of kind 'ldap': its users are linked through
-- `federated_identities` like any brokered identity, and share the link
-- policy and mappers (mapper values name LDAP attributes). There is no
-- login-page button: a directory user signs in with the password form and
-- rIDM binds as them. The directory owns the password, so a linked user
-- keeps no local hash.
--
-- The service account's bind password is stored where every provider keeps
-- its secret, `identity_providers.client_secret_enc`, so master key
-- rotation re-encrypts it with the rest.
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind IN ('oidc', 'oauth2', 'saml', 'ldap'));

CREATE TABLE ldap_identity_providers (
    idp_id                    uuid        PRIMARY KEY,
    tenant_id                 uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- ldap://host[:port] or ldaps://host[:port]. Plain ldap:// without
    -- StartTLS is refused unless the host is loopback.
    url                       text        NOT NULL,
    starttls                  boolean     NOT NULL DEFAULT false,
    -- PEM certificate(s) the directory's certificate must chain to; none
    -- trusts the platform's roots.
    ca_certificate            text,
    vendor                    text        NOT NULL DEFAULT 'other',
    -- The service account that searches (and, when writable, writes); none
    -- searches anonymously.
    bind_dn                   text,
    users_dn                  text        NOT NULL,
    user_object_filter        text        NOT NULL,
    search_scope              text        NOT NULL DEFAULT 'subtree',
    username_attribute        text        NOT NULL,
    -- The attributes a sign-in identifier is matched against.
    login_attributes          text[]      NOT NULL,
    -- The attribute that never changes for an entry (entryUUID, objectGUID):
    -- the linked identity's external subject.
    uuid_attribute            text        NOT NULL,
    edit_mode                 text        NOT NULL DEFAULT 'read_only',
    -- Incremental sync every N minutes (0 = none), a full one (which also
    -- disables users who left the directory) every M hours.
    sync_interval_minutes     integer     NOT NULL DEFAULT 60,
    full_sync_interval_hours  integer     NOT NULL DEFAULT 24,
    -- Group sync, when a base is set.
    groups_dn                 text,
    group_object_filter       text        NOT NULL,
    group_name_attribute      text        NOT NULL DEFAULT 'cn',
    group_member_attribute    text        NOT NULL DEFAULT 'member',
    -- 'dn': member values are entry DNs (groupOfNames, AD); 'username':
    -- they are usernames (posixGroup memberUid).
    group_membership          text        NOT NULL DEFAULT 'dn',
    -- Where synced groups are created; none makes them top-level.
    group_parent_id           uuid,
    timeout_secs              integer     NOT NULL DEFAULT 10,
    -- Sync status.
    last_sync_at              timestamptz,
    last_full_sync_at         timestamptz,
    last_sync_error           text,
    last_sync_stats           jsonb,
    -- The newest modification time the last sync saw (the directory's
    -- generalized time), where the next incremental sync starts.
    sync_cursor               text,
    created_at                timestamptz NOT NULL DEFAULT now(),
    updated_at                timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_parent_id) REFERENCES groups(tenant_id, id) ON DELETE SET NULL (group_parent_id),
    CONSTRAINT ldap_idps_url_check CHECK (url ~ '^ldaps?://' AND length(url) <= 512),
    CONSTRAINT ldap_idps_vendor_check CHECK (vendor IN ('active_directory', 'openldap', 'other')),
    CONSTRAINT ldap_idps_scope_check CHECK (search_scope IN ('subtree', 'one')),
    CONSTRAINT ldap_idps_edit_mode_check CHECK (edit_mode IN ('read_only', 'writable')),
    CONSTRAINT ldap_idps_membership_check CHECK (group_membership IN ('dn', 'username')),
    CONSTRAINT ldap_idps_login_attributes_check CHECK (cardinality(login_attributes) BETWEEN 1 AND 5),
    CONSTRAINT ldap_idps_sync_interval_check CHECK (sync_interval_minutes = 0 OR sync_interval_minutes BETWEEN 5 AND 10080),
    CONSTRAINT ldap_idps_full_sync_check CHECK (full_sync_interval_hours BETWEEN 1 AND 720),
    CONSTRAINT ldap_idps_timeout_check CHECK (timeout_secs BETWEEN 1 AND 60),
    CONSTRAINT ldap_idps_ca_length CHECK (length(ca_certificate) <= 65536),
    CONSTRAINT ldap_idps_error_length CHECK (length(last_sync_error) <= 1000)
);

CREATE TRIGGER ldap_identity_providers_set_updated_at BEFORE UPDATE ON ldap_identity_providers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The sync job pages through the directories that sync, across tenants.
CREATE INDEX ldap_idps_sync_due_idx ON ldap_identity_providers (tenant_id, idp_id)
    WHERE sync_interval_minutes > 0;

SELECT enable_tenant_rls('ldap_identity_providers');

-- A directory identity remembers its entry's DN (group members name DNs)
-- and whether the sync disabled the user because the entry left the
-- directory or was disabled there, so its return re-enables them.
ALTER TABLE federated_identities
    ADD COLUMN external_dn text,
    ADD COLUMN disabled_by_directory boolean NOT NULL DEFAULT false;

CREATE INDEX federated_identities_dn_idx ON federated_identities (tenant_id, idp_id, lower(external_dn))
    WHERE external_dn IS NOT NULL;
CREATE INDEX federated_identities_username_idx ON federated_identities (tenant_id, idp_id, external_username);

-- The rIDM groups a directory's group sync owns: created, renamed, filled
-- and deleted by the sync (members from other sources are left alone).
CREATE TABLE ldap_group_links (
    tenant_id    uuid        NOT NULL,
    idp_id       uuid        NOT NULL,
    -- The directory group's uuid attribute value.
    external_id  text        NOT NULL,
    group_id     uuid        NOT NULL,
    external_dn  text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, idp_id, external_id),
    CONSTRAINT ldap_group_links_group_key UNIQUE (tenant_id, group_id),
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups(tenant_id, id) ON DELETE CASCADE
);

SELECT enable_tenant_rls('ldap_group_links');
