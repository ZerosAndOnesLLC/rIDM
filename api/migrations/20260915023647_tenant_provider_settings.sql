-- 0010: per-tenant provider configuration with secrets (CAPTCHA, SMTP, SMS),
-- encrypted at rest with the master key.
CREATE TABLE tenant_provider_settings (
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind         text        NOT NULL,
    config_enc   bytea       NOT NULL,
    key_version  integer     NOT NULL DEFAULT 1,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kind),
    CONSTRAINT tenant_provider_settings_kind_check CHECK (kind IN ('captcha', 'smtp', 'sms'))
);

-- The primary key already leads with tenant_id; `id`-less table, so the
-- rotation job addresses rows by (tenant_id, kind).
SELECT enable_tenant_rls('tenant_provider_settings');
