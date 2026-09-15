-- 0012: invitations. The token is stored hashed; the email is the invitee's.
CREATE TABLE invitations (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email        text        NOT NULL,
    roles        uuid[]      NOT NULL DEFAULT '{}',
    groups       uuid[]      NOT NULL DEFAULT '{}',
    org_id       uuid,
    token_hash   bytea       NOT NULL,
    invited_by   uuid,
    expires_at   timestamptz NOT NULL,
    accepted_at  timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT invitations_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT invitations_tenant_token_key UNIQUE (tenant_id, token_hash),
    CONSTRAINT invitations_email_lower CHECK (email = lower(email))
);

CREATE INDEX invitations_email_idx ON invitations (tenant_id, email, created_at DESC);
CREATE INDEX invitations_pending_idx ON invitations (tenant_id, expires_at) WHERE accepted_at IS NULL AND revoked_at IS NULL;

SELECT enable_tenant_rls('invitations');
