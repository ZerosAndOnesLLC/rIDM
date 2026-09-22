-- Phase 13.2: SAML 2.0 identity providers upstream (rIDM as a service
-- provider). A SAML upstream is an `identity_providers` row of kind 'saml':
-- it shares the login-page button, account linking, link policy and
-- mappers of OIDC and OAuth 2.0 providers. It has no client id, secret or
-- endpoints of that kind; its SAML settings live in
-- `saml_identity_providers`. rIDM signs and decrypts with the tenant's SAML
-- keys (`saml_signing_keys`, 13.1), so there is no key material here.
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind IN ('oidc', 'oauth2', 'saml'));

CREATE TABLE saml_identity_providers (
    idp_id                       uuid        PRIMARY KEY,
    tenant_id                    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The upstream IdP's entity ID: the `Issuer` of what it sends.
    entity_id                    text        NOT NULL,
    sso_url                      text        NOT NULL,
    sso_binding                  text        NOT NULL DEFAULT 'redirect',
    slo_url                      text,
    slo_binding                  text        NOT NULL DEFAULT 'redirect',
    -- base64 DER certificates the IdP signs with (several during its
    -- rollover). Nothing unsigned is ever accepted, so one is required.
    signing_certificates         text[]      NOT NULL,
    -- The NameID format asked for in `NameIDPolicy`; none asks for nothing.
    name_id_format               text,
    sign_requests                boolean     NOT NULL DEFAULT true,
    -- The assertion itself must carry a signature (a signed Response
    -- around an unsigned assertion is refused).
    want_assertions_signed       boolean     NOT NULL DEFAULT true,
    require_encrypted_assertions boolean     NOT NULL DEFAULT false,
    force_authn                  boolean     NOT NULL DEFAULT false,
    -- `AuthnContextClassRef`s to request (Comparison `exact`); empty asks
    -- for none.
    authn_context_class_refs     text[]      NOT NULL DEFAULT '{}',
    -- Unsolicited responses (IdP-initiated sign-in) are refused unless the
    -- provider opts in; they land on this client's `initiate_login_uri`, or
    -- on the account console when it is null.
    allow_unsolicited            boolean     NOT NULL DEFAULT false,
    unsolicited_client_id        text,
    -- Where the IdP publishes its metadata: the daily refresh job fetches
    -- it and takes the endpoints and certificates from it.
    metadata_url                 text,
    metadata_refreshed_at        timestamptz,
    metadata_error               text,
    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_at                   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, idp_id) REFERENCES identity_providers(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT saml_idps_tenant_entity_key UNIQUE (tenant_id, entity_id),
    CONSTRAINT saml_idps_entity_length CHECK (length(entity_id) BETWEEN 1 AND 1024),
    CONSTRAINT saml_idps_certificates_check CHECK (cardinality(signing_certificates) BETWEEN 1 AND 10),
    CONSTRAINT saml_idps_sso_binding_check CHECK (sso_binding IN ('redirect', 'post')),
    CONSTRAINT saml_idps_slo_binding_check CHECK (slo_binding IN ('redirect', 'post')),
    CONSTRAINT saml_idps_name_id_check
        CHECK (name_id_format IS NULL OR name_id_format IN ('persistent', 'transient', 'email', 'unspecified')),
    CONSTRAINT saml_idps_contexts_check CHECK (cardinality(authn_context_class_refs) <= 10),
    CONSTRAINT saml_idps_metadata_error_length CHECK (length(metadata_error) <= 1000)
);

CREATE TRIGGER saml_identity_providers_set_updated_at BEFORE UPDATE ON saml_identity_providers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- The metadata refresh job pages through the providers that have a URL,
-- across tenants.
CREATE INDEX saml_idps_metadata_due_idx ON saml_identity_providers (tenant_id, idp_id)
    WHERE metadata_url IS NOT NULL;

SELECT enable_tenant_rls('saml_identity_providers');
