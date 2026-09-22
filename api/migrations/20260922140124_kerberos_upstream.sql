-- Phase 13.4: Kerberos / SPNEGO desktop sign-in. A Kerberos realm is an
-- `identity_providers` row of kind 'kerberos'. It has no login-page
-- redirect: the login page asks the browser for a Negotiate token (on its
-- own from the provider's trusted networks, or when the user clicks), and
-- rIDM checks the ticket inside against the service's keytab.
--
-- The keytab is the provider's secret and lives where every provider keeps
-- one, `identity_providers.client_secret_enc` (base64 of the file), so
-- master key rotation re-encrypts it. `keytab_entries` describes what it
-- holds (principal, key version, encryption type; never a key) for the
-- console.
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind IN ('oidc', 'oauth2', 'saml', 'ldap', 'kerberos'));

CREATE TABLE kerberos_identity_providers (
    idp_id                uuid        PRIMARY KEY,
    tenant_id             uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The service tickets are issued for, HTTP/<host>@<REALM>.
    service_principal     text        NOT NULL,
    -- The client realms whose users may sign in (upper-case).
    realms                text[]      NOT NULL,
    keytab_entries        jsonb       NOT NULL DEFAULT '[]',
    -- How a principal names a user: 'local_part' (alice) or 'principal'
    -- (alice@EXAMPLE.COM).
    name_form             text        NOT NULL DEFAULT 'local_part',
    -- A directory (an 'ldap' provider) that owns these users: the name is
    -- looked up in it by `ldap_attribute` and the entry imported or
    -- refreshed through it. Without one, local accounts are matched.
    ldap_idp_id           uuid,
    ldap_attribute        text,
    -- Without a directory: sign in the local account whose username is
    -- the name, and create one when none is (both by the provider's link).
    match_username        boolean     NOT NULL DEFAULT true,
    create_users          boolean     NOT NULL DEFAULT false,
    -- Where the login page tries Kerberos without being asked (CIDRs); an
    -- empty list leaves it to the button.
    trusted_networks      text[]      NOT NULL DEFAULT '{}',
    -- Allowed difference between the client's clock and rIDM's.
    max_skew_seconds      integer     NOT NULL DEFAULT 300,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, ldap_idp_id) REFERENCES identity_providers(tenant_id, id)
        ON DELETE SET NULL (ldap_idp_id),
    CONSTRAINT kerberos_idps_principal_check
        CHECK (length(service_principal) BETWEEN 3 AND 512 AND position('@' IN service_principal) > 0),
    CONSTRAINT kerberos_idps_realms_check CHECK (cardinality(realms) BETWEEN 1 AND 20),
    CONSTRAINT kerberos_idps_name_form_check CHECK (name_form IN ('local_part', 'principal')),
    CONSTRAINT kerberos_idps_ldap_attribute_check CHECK (length(ldap_attribute) <= 128),
    CONSTRAINT kerberos_idps_networks_check CHECK (cardinality(trusted_networks) <= 100),
    CONSTRAINT kerberos_idps_skew_check CHECK (max_skew_seconds BETWEEN 30 AND 900),
    CONSTRAINT kerberos_idps_entries_check CHECK (jsonb_typeof(keytab_entries) = 'array')
);

CREATE TRIGGER kerberos_identity_providers_set_updated_at BEFORE UPDATE ON kerberos_identity_providers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- One provider per service principal in a tenant: a ticket names the
-- service it is for, and that picks the provider.
CREATE UNIQUE INDEX kerberos_idps_principal_key
    ON kerberos_identity_providers (tenant_id, lower(service_principal));

SELECT enable_tenant_rls('kerberos_identity_providers');
