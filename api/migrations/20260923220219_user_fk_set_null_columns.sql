-- `clients.service_account_user_id` and `device_codes.user_id` reference
-- `users (tenant_id, id)` with ON DELETE SET NULL but no column list, which
-- nulls *every* referencing column: deleting a user who was a client's
-- service account, or who approved a device code, tried to set `tenant_id`
-- to NULL as well and its NOT NULL refused. The purge of soft-deleted users
-- deletes a whole tenant's rows in one statement, so one such user failed
-- the purge for the whole tenant, every day (the same bug
-- 20260919235908_organization_fk_set_null_columns fixed for organizations).
--
-- The constraints come back NOT VALID so this takes its locks for an
-- instant; the next migration validates them without blocking writes.
ALTER TABLE clients DROP CONSTRAINT clients_tenant_id_service_account_user_id_fkey;
ALTER TABLE clients ADD CONSTRAINT clients_service_account_user_fk
    FOREIGN KEY (tenant_id, service_account_user_id) REFERENCES users(tenant_id, id)
    ON DELETE SET NULL (service_account_user_id) NOT VALID;

ALTER TABLE device_codes DROP CONSTRAINT device_codes_tenant_id_user_id_fkey;
ALTER TABLE device_codes ADD CONSTRAINT device_codes_user_fk
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id)
    ON DELETE SET NULL (user_id) NOT VALID;
