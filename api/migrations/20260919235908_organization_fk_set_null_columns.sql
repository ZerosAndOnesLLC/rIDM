-- The organization foreign keys are composite, `(tenant_id, org_id)`, and
-- ON DELETE SET NULL without a column list nulls *every* referencing column:
-- deleting an organization tried to set `tenant_id` to NULL as well, which its
-- NOT NULL constraint refused. Deleting an organization that anything pointed
-- at therefore failed.
--
-- Postgres 15 and later take the column to null, which is what was meant.
ALTER TABLE users DROP CONSTRAINT users_org_fk;
ALTER TABLE users ADD CONSTRAINT users_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id)
    ON DELETE SET NULL (org_id);

ALTER TABLE invitations DROP CONSTRAINT invitations_org_fk;
ALTER TABLE invitations ADD CONSTRAINT invitations_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id)
    ON DELETE SET NULL (org_id);

ALTER TABLE sso_sessions DROP CONSTRAINT sso_sessions_org_fk;
ALTER TABLE sso_sessions ADD CONSTRAINT sso_sessions_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id)
    ON DELETE SET NULL (org_id);

ALTER TABLE refresh_tokens DROP CONSTRAINT refresh_tokens_org_fk;
ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_tokens_org_fk
    FOREIGN KEY (tenant_id, org_id) REFERENCES organizations(tenant_id, id)
    ON DELETE SET NULL (org_id);
