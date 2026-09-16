-- 0020: device authorization grant (RFC 8628): the audit trail of device
-- codes. The live codes themselves live in Valkey until they are approved,
-- denied, consumed or expire.

CREATE TABLE device_codes (
    id           uuid        PRIMARY KEY,
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id    uuid        NOT NULL,
    user_id      uuid,
    user_code    text        NOT NULL,
    scopes       text[]      NOT NULL DEFAULT '{}',
    status       text        NOT NULL DEFAULT 'pending',
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz,
    consumed_at  timestamptz,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE SET NULL,
    CONSTRAINT device_codes_status_check CHECK (status IN ('pending', 'approved', 'denied', 'consumed'))
);

CREATE INDEX device_codes_tenant_idx ON device_codes (tenant_id, created_at DESC);
CREATE INDEX device_codes_user_idx ON device_codes (tenant_id, user_id) WHERE user_id IS NOT NULL;

SELECT enable_tenant_rls('device_codes');
