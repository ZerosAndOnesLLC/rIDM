-- Audit chain bookkeeping and the `features` scope (Phase 12.5).
--
-- One row per audit chain (a tenant's, or the global one under the nil
-- UUID) holds three positions in it:
--
-- * the head — the newest row's seq and hash, kept by the audit writer in
--   the same transaction as the row, so the next row's link is one indexed
--   read and a reader can compare an export against it;
-- * the verified checkpoint — how far the daily verification job has walked
--   the chain and found it intact, so the next pass starts there instead of
--   at the oldest row; and where it last found the chain broken;
-- * the sink cursor — how far the export sink (`AUDIT_SINK_URL`) has shipped
--   the chain. The sink reads rows from here rather than from memory, so an
--   outage of the receiver or a restart of rIDM loses nothing: it catches up.

CREATE TABLE audit_chains (
    chain_id       uuid        PRIMARY KEY,
    tenant_id      uuid,
    head_seq       bigint      NOT NULL,
    head_hash      bytea       NOT NULL,
    verified_seq   bigint,
    verified_hash  bytea,
    verified_at    timestamptz,
    broken_at_seq  bigint,
    broken_reason  text,
    broken_at      timestamptz,
    sink_seq       bigint,
    sink_at        timestamptz
);

INSERT INTO audit_chains (chain_id, tenant_id, head_seq, head_hash)
SELECT DISTINCT ON (chain_id) chain_id, tenant_id, seq, hash
  FROM audit_events
 ORDER BY chain_id, seq DESC;

SELECT enable_tenant_rls('audit_chains');

-- Which sink the cursors above belong to. Pointing AUDIT_SINK_URL somewhere
-- new starts that sink at the current heads rather than replaying history.
CREATE TABLE audit_sink_state (
    id          smallint    PRIMARY KEY CHECK (id = 1),
    target      text        NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now()
);

-- `features`: an application asks for it to learn which of the tenant's
-- feature flags are on for the signed-in user (a `features` claim).
CREATE OR REPLACE FUNCTION seed_default_scopes(p_tenant_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    previous text := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    INSERT INTO scopes (tenant_id, name, description, claims, is_default) VALUES
        (p_tenant_id, 'openid',         'Sign you in',                       '{sub}', true),
        (p_tenant_id, 'profile',        'Your name and basic profile',       '{name,family_name,given_name,middle_name,nickname,preferred_username,profile,picture,website,gender,birthdate,zoneinfo,locale,updated_at}', false),
        (p_tenant_id, 'email',          'Your email address',                '{email,email_verified}', false),
        (p_tenant_id, 'phone',          'Your phone number',                 '{phone_number,phone_number_verified}', false),
        (p_tenant_id, 'address',        'Your postal address',               '{address}', false),
        (p_tenant_id, 'offline_access', 'Stay signed in (refresh tokens)',   '{}', false),
        (p_tenant_id, 'features',       'Which features are turned on for you', '{}', false)
    ON CONFLICT (tenant_id, name) DO NOTHING;
    PERFORM set_config('app.bypass_rls', COALESCE(previous, ''), true);
END;
$$;

SELECT seed_default_scopes(id) FROM tenants;
