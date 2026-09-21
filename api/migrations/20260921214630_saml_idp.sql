-- Phase 13.1: rIDM as a SAML 2.0 identity provider.

-- A SAML service provider is a client (client_type 'saml'): it shares the
-- sign-in flows, consent, session participation, roles and audit of OIDC
-- clients. It has no redirect URIs, grants or secret, so no OAuth endpoint
-- will serve it; its SAML settings live in `saml_service_providers`.
ALTER TABLE clients DROP CONSTRAINT clients_type_check;
ALTER TABLE clients ADD CONSTRAINT clients_type_check
    CHECK (client_type IN ('spa', 'web', 'native', 'machine', 'device', 'saml'));

CREATE TABLE saml_service_providers (
    client_id                uuid        PRIMARY KEY,
    tenant_id                uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_id                text        NOT NULL,
    -- Assertion consumer services (HTTP-POST); the array position is the
    -- `AssertionConsumerServiceIndex`, and the first is the default.
    acs_urls                 text[]      NOT NULL,
    slo_url                  text,
    slo_binding              text        NOT NULL DEFAULT 'redirect',
    name_id_format           text        NOT NULL DEFAULT 'persistent',
    -- base64 DER certificates the SP signs requests with (several during a
    -- rollover), and the one assertions are encrypted to.
    signing_certificates     text[]      NOT NULL DEFAULT '{}',
    encryption_certificate   text,
    require_signed_requests  boolean     NOT NULL DEFAULT false,
    sign_response            boolean     NOT NULL DEFAULT true,
    sign_assertion           boolean     NOT NULL DEFAULT true,
    encrypt_assertion        boolean     NOT NULL DEFAULT false,
    data_encryption          text        NOT NULL DEFAULT 'aes256-gcm',
    key_transport            text        NOT NULL DEFAULT 'rsa-oaep-mgf1p',
    -- Unsolicited responses (IdP-initiated sign-in) are refused unless the
    -- SP opts in.
    allow_idp_initiated      boolean     NOT NULL DEFAULT false,
    default_relay_state      text,
    -- [{claim, name, name_format, friendly_name}]; empty releases every
    -- claim the client's scopes allow, named after the claim.
    attributes               jsonb       NOT NULL DEFAULT '[]',
    assertion_ttl_secs       integer     NOT NULL DEFAULT 300,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT saml_sps_tenant_entity_key UNIQUE (tenant_id, entity_id),
    CONSTRAINT saml_sps_acs_check CHECK (cardinality(acs_urls) BETWEEN 1 AND 32),
    CONSTRAINT saml_sps_slo_binding_check CHECK (slo_binding IN ('redirect', 'post')),
    CONSTRAINT saml_sps_name_id_check
        CHECK (name_id_format IN ('persistent', 'transient', 'email', 'unspecified')),
    CONSTRAINT saml_sps_data_encryption_check
        CHECK (data_encryption IN ('aes256-gcm', 'aes128-gcm', 'aes256-cbc', 'aes128-cbc')),
    CONSTRAINT saml_sps_key_transport_check
        CHECK (key_transport IN ('rsa-oaep-mgf1p', 'rsa-oaep-sha256')),
    CONSTRAINT saml_sps_encryption_needs_cert_check
        CHECK (NOT encrypt_assertion OR encryption_certificate IS NOT NULL),
    CONSTRAINT saml_sps_ttl_check CHECK (assertion_ttl_secs BETWEEN 30 AND 3600)
);

CREATE TRIGGER saml_service_providers_set_updated_at BEFORE UPDATE ON saml_service_providers
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

SELECT enable_tenant_rls('saml_service_providers');

-- The IdP's SAML signing keys. They are not the JWT signing keys: SPs pin
-- the certificate from metadata, so these never rotate on a timer. An
-- operator adds a `pending` key (published in metadata at once), activates
-- it once SPs have the new metadata, then removes the `retiring` one.
CREATE TABLE saml_signing_keys (
    id               uuid        PRIMARY KEY,
    tenant_id        uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- RSA-2048+ private key, PKCS#8 DER, encrypted like `signing_keys`.
    private_key_enc  bytea       NOT NULL,
    key_version      integer     NOT NULL,
    -- Self-signed X.509 certificate (DER) SPs pin.
    certificate      bytea       NOT NULL,
    status           text        NOT NULL,
    not_after        timestamptz NOT NULL,
    activated_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT saml_signing_keys_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT saml_signing_keys_status_check CHECK (status IN ('pending', 'active', 'retiring'))
);

-- One active key per tenant; the partial index also settles a race
-- between nodes creating the first one.
CREATE UNIQUE INDEX saml_signing_keys_one_active_idx ON saml_signing_keys (tenant_id)
    WHERE status = 'active';
CREATE INDEX saml_signing_keys_tenant_idx ON saml_signing_keys (tenant_id, created_at);

CREATE TRIGGER saml_signing_keys_set_updated_at BEFORE UPDATE ON saml_signing_keys
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

SELECT enable_tenant_rls('saml_signing_keys');
