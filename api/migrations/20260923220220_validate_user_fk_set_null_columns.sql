-- Validation takes SHARE UPDATE EXCLUSIVE: reads and writes go on meanwhile.
ALTER TABLE clients VALIDATE CONSTRAINT clients_service_account_user_fk;
ALTER TABLE device_codes VALIDATE CONSTRAINT device_codes_user_fk;
