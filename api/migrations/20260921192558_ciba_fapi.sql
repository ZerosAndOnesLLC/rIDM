-- Phase 12.6: client-initiated backchannel authentication (OpenID CIBA Core
-- 1.0) and the FAPI 2.0 security profile.

-- Client metadata. `backchannel_token_delivery_mode` is `poll` or `ping`
-- (push is not offered); ping needs the client's notification endpoint.
-- `security_profile` `fapi2` holds the client to the FAPI 2.0 Security
-- Profile everywhere it authenticates and asks for tokens.
-- `require_pushed_authorization_requests` (RFC 9126 §6) refuses an
-- authorization request that did not come through PAR.
ALTER TABLE clients
    ADD COLUMN backchannel_token_delivery_mode text,
    ADD COLUMN backchannel_client_notification_endpoint text,
    ADD COLUMN security_profile text NOT NULL DEFAULT 'none',
    ADD COLUMN require_pushed_authorization_requests boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT clients_backchannel_mode_check
        CHECK (backchannel_token_delivery_mode IN ('poll', 'ping')),
    ADD CONSTRAINT clients_security_profile_check
        CHECK (security_profile IN ('none', 'fapi2'));

-- Backchannel authentication requests: the audit trail, and the list the
-- user's account console shows. The live request (what the token endpoint
-- polls, and the client's notification token) is in Valkey under
-- `auth_req_hash` until it is decided, collected or expires.
CREATE TABLE ciba_requests (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    -- base64url(SHA-256(auth_req_id)); the id itself is only ever returned
    -- to the client.
    auth_req_hash   text        NOT NULL,
    scopes          text[]      NOT NULL DEFAULT '{}',
    binding_message text,
    acr_values      text[]      NOT NULL DEFAULT '{}',
    delivery_mode   text        NOT NULL,
    status          text        NOT NULL DEFAULT 'pending',
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    decided_at      timestamptz,
    consumed_at     timestamptz,
    FOREIGN KEY (tenant_id, client_id) REFERENCES clients(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT ciba_requests_status_check
        CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    CONSTRAINT ciba_requests_mode_check CHECK (delivery_mode IN ('poll', 'ping'))
);

CREATE INDEX ciba_requests_tenant_idx ON ciba_requests (tenant_id, created_at DESC);
-- The account console's "waiting for you" list, and the per-user cap.
CREATE INDEX ciba_requests_pending_idx ON ciba_requests (tenant_id, user_id, expires_at)
    WHERE status = 'pending';

SELECT enable_tenant_rls('ciba_requests');
