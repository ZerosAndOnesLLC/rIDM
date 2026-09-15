-- 0016: outbound webhooks with a delivery log, and per-tenant IP rules.

CREATE TABLE webhooks (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          text        NOT NULL,
    url           text        NOT NULL,
    -- HMAC signing secret, encrypted under the master key
    secret_enc    bytea       NOT NULL,
    key_version   integer     NOT NULL,
    -- event names: exact (`user.created`), prefix (`user.*`) or `*`
    events        text[]      NOT NULL DEFAULT '{}',
    enabled       boolean     NOT NULL DEFAULT true,
    -- static headers added to every delivery
    headers       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    max_attempts  integer     NOT NULL DEFAULT 8,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webhooks_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT webhooks_name_length CHECK (length(name) BETWEEN 1 AND 255),
    CONSTRAINT webhooks_max_attempts_check CHECK (max_attempts BETWEEN 1 AND 20)
);

CREATE INDEX webhooks_tenant_idx ON webhooks (tenant_id, created_at, id);

CREATE TRIGGER webhooks_set_updated_at BEFORE UPDATE ON webhooks
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

SELECT enable_tenant_rls('webhooks');

CREATE TABLE webhook_deliveries (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL,
    webhook_id       uuid        NOT NULL,
    event_id         uuid        NOT NULL,
    event_name       text        NOT NULL,
    payload          jsonb       NOT NULL,
    status           text        NOT NULL DEFAULT 'pending',
    attempts         integer     NOT NULL DEFAULT 0,
    max_attempts     integer     NOT NULL,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_status      integer,
    last_error       text,
    response_snippet text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    delivered_at     timestamptz,
    FOREIGN KEY (tenant_id, webhook_id) REFERENCES webhooks(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT webhook_deliveries_status_check CHECK (status IN ('pending', 'sending', 'delivered', 'failed', 'dead'))
);

CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (tenant_id, next_attempt_at)
    WHERE status IN ('pending', 'failed');
CREATE INDEX webhook_deliveries_webhook_idx ON webhook_deliveries (tenant_id, webhook_id, created_at DESC);

SELECT enable_tenant_rls('webhook_deliveries');

CREATE TABLE ip_rules (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- NULL applies to the whole tenant; otherwise to one client
    client_id    uuid,
    action       text        NOT NULL,
    cidr         text        NOT NULL,
    description  text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ip_rules_action_check CHECK (action IN ('allow', 'deny')),
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX ip_rules_scope_cidr_key
    ON ip_rules (tenant_id, COALESCE(client_id, '00000000-0000-0000-0000-000000000000'::uuid), cidr);
CREATE INDEX ip_rules_tenant_idx ON ip_rules (tenant_id, client_id);

CREATE TRIGGER ip_rules_set_updated_at BEFORE UPDATE ON ip_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

SELECT enable_tenant_rls('ip_rules');
