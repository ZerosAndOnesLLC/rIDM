-- 0011: outbound messaging: per-tenant/locale templates and a delivery queue
-- with retries and dead-lettering.

CREATE TABLE message_templates (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel     text        NOT NULL,
    event       text        NOT NULL,
    locale      text        NOT NULL,
    subject     text,
    body_text   text        NOT NULL,
    body_html   text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT message_templates_channel_check CHECK (channel IN ('email', 'sms')),
    CONSTRAINT message_templates_key UNIQUE (tenant_id, channel, event, locale)
);

CREATE TRIGGER message_templates_set_updated_at BEFORE UPDATE ON message_templates
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE outbound_messages (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel          text        NOT NULL,
    event            text        NOT NULL,
    recipient        text        NOT NULL,
    subject          text,
    body_text        text        NOT NULL,
    body_html        text,
    headers          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    status           text        NOT NULL DEFAULT 'queued',
    attempts         integer     NOT NULL DEFAULT 0,
    max_attempts     integer     NOT NULL DEFAULT 6,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz,
    CONSTRAINT outbound_messages_channel_check CHECK (channel IN ('email', 'sms')),
    CONSTRAINT outbound_messages_status_check CHECK (status IN ('queued', 'sending', 'sent', 'dead'))
);

CREATE INDEX outbound_messages_due_idx ON outbound_messages (tenant_id, status, next_attempt_at);
CREATE INDEX outbound_messages_recipient_idx ON outbound_messages (tenant_id, recipient, created_at DESC);

SELECT enable_tenant_rls('message_templates');
SELECT enable_tenant_rls('outbound_messages');
