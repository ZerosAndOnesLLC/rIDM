-- A refresh token mints tokens long after the browser session is gone (an
-- offline_access grant outlives it), and those tokens must keep naming the
-- organization the sign-in acted in. The family carries it, as it already
-- carries auth_time, amr and acr.
--
-- Deleting the organization clears it rather than the token: the grant is
-- still good, it simply no longer acts anywhere in particular.
ALTER TABLE refresh_tokens ADD COLUMN org_id uuid;
ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_tokens_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id) ON DELETE SET NULL;
