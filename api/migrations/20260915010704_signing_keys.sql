-- 0004: per-tenant signing keys. Private keys are encrypted at rest with the
-- master key (KeyEncryptor); key_version records which master-key generation
-- produced the ciphertext so rotation can re-encrypt incrementally.

CREATE TABLE signing_keys (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kid              text        NOT NULL,
    alg              text        NOT NULL,
    public_jwk       jsonb       NOT NULL,
    private_key_enc  bytea       NOT NULL,
    key_version      integer     NOT NULL,
    status           text        NOT NULL DEFAULT 'active',
    not_before       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT signing_keys_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT signing_keys_tenant_kid_key UNIQUE (tenant_id, kid),
    CONSTRAINT signing_keys_alg_check CHECK (alg IN ('RS256', 'RS384', 'RS512', 'ES256', 'EdDSA')),
    CONSTRAINT signing_keys_status_check CHECK (status IN ('pending', 'active', 'retiring', 'revoked'))
);

CREATE INDEX signing_keys_tenant_status_idx ON signing_keys (tenant_id, status, alg);
CREATE INDEX signing_keys_tenant_expires_idx ON signing_keys (tenant_id, expires_at) WHERE expires_at IS NOT NULL;

CREATE TRIGGER signing_keys_set_updated_at BEFORE UPDATE ON signing_keys
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

SELECT enable_tenant_rls('signing_keys');
