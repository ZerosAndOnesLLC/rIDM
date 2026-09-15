-- 0009: login attempt log (brute-force protection, audit) and terms acceptance.

CREATE TABLE login_attempts (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identifier  text        NOT NULL,
    ip          text,
    success     boolean     NOT NULL,
    reason      text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX login_attempts_identifier_idx ON login_attempts (tenant_id, identifier, created_at DESC);
CREATE INDEX login_attempts_ip_idx ON login_attempts (tenant_id, ip, created_at DESC) WHERE ip IS NOT NULL;
CREATE INDEX login_attempts_created_idx ON login_attempts (tenant_id, created_at);

SELECT enable_tenant_rls('login_attempts');

ALTER TABLE users ADD COLUMN terms_accepted_at timestamptz;
