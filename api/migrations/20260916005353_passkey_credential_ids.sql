-- Passkeys (WebAuthn) are looked up by the credential id the authenticator
-- presents, before the user is known (discoverable sign-in), and one
-- credential id may belong to one account only.
ALTER TABLE credentials ADD COLUMN external_id text;

CREATE UNIQUE INDEX credentials_external_id_idx
    ON credentials (tenant_id, type, external_id)
    WHERE external_id IS NOT NULL;
