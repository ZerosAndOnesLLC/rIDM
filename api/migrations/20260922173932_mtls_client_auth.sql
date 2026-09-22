-- Phase 13.5: mutual-TLS client authentication and certificate-bound tokens
-- (RFC 8705).

-- Two more token endpoint authentication methods (RFC 8705 §2):
-- `tls_client_auth`, a certificate from a CA the tenant trusts whose subject
-- is the one registered here, and `self_signed_tls_client_auth`, a
-- certificate registered in the client's JWK Set (`x5c`).
ALTER TABLE clients DROP CONSTRAINT clients_auth_method_check;
ALTER TABLE clients ADD CONSTRAINT clients_auth_method_check CHECK (token_endpoint_auth_method IN
    ('none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt',
     'tls_client_auth', 'self_signed_tls_client_auth'));

-- The subject a `tls_client_auth` certificate must carry (RFC 8705
-- §2.1.2): exactly one of these is set for such a client, none otherwise.
-- `tls_client_certificate_bound_access_tokens` (§3.4) binds every access
-- token to the certificate the client presented (`cnf.x5t#S256`).
ALTER TABLE clients
    ADD COLUMN tls_client_auth_subject_dn text,
    ADD COLUMN tls_client_auth_san_dns text,
    ADD COLUMN tls_client_auth_san_uri text,
    ADD COLUMN tls_client_auth_san_ip text,
    ADD COLUMN tls_client_auth_san_email text,
    ADD COLUMN tls_client_certificate_bound_access_tokens boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT clients_tls_subject_check CHECK (
        num_nonnulls(tls_client_auth_subject_dn, tls_client_auth_san_dns,
                     tls_client_auth_san_uri, tls_client_auth_san_ip,
                     tls_client_auth_san_email)
        = CASE WHEN token_endpoint_auth_method = 'tls_client_auth' THEN 1 ELSE 0 END),
    ADD CONSTRAINT clients_tls_subject_length_check CHECK (
        length(tls_client_auth_subject_dn) <= 1024 AND length(tls_client_auth_san_dns) <= 253
        AND length(tls_client_auth_san_uri) <= 2048 AND length(tls_client_auth_san_ip) <= 45
        AND length(tls_client_auth_san_email) <= 320);

-- A public client's refresh tokens are bound to the certificate it
-- presented (RFC 8705 §4): base64url(SHA-256(DER)).
ALTER TABLE refresh_tokens ADD COLUMN mtls_x5t text;

-- The certificate authorities whose certificates `tls_client_auth` clients
-- of the tenant may present. An intermediate may be listed on its own: the
-- chain only has to reach one of these.
CREATE TABLE mtls_trust_anchors (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            text        NOT NULL,
    certificate_pem text        NOT NULL,
    -- RFC 4514 subject, and base64url(SHA-256(DER)) for display and
    -- de-duplication.
    subject         text        NOT NULL,
    fingerprint     text        NOT NULL,
    not_before      timestamptz NOT NULL,
    not_after       timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT mtls_trust_anchors_name_check CHECK (length(name) BETWEEN 1 AND 255),
    CONSTRAINT mtls_trust_anchors_pem_check CHECK (length(certificate_pem) <= 16384),
    CONSTRAINT mtls_trust_anchors_fingerprint_key UNIQUE (tenant_id, fingerprint)
);

CREATE INDEX mtls_trust_anchors_tenant_idx ON mtls_trust_anchors (tenant_id, created_at);

SELECT enable_tenant_rls('mtls_trust_anchors');
