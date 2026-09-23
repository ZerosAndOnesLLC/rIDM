-- Phase 13.6: master-key generations held by an HSM or a cloud KMS.
--
-- With a key custody backend configured (`KEY_WRAPPER`), each master-key
-- generation is a random 256-bit data key that the backend wrapped; only the
-- wrapped form is stored here, and every node asks the backend to unwrap it at
-- start-up. Rows are encrypted locally with the data key exactly as they are
-- under `MASTER_KEY`, and the generation number in every `*_enc` blob and
-- `key_version` column is this table's `version`, so generations from the
-- environment and from here can be mixed while `rotate-master-key` moves rows
-- from one to the other.
--
-- Deployment-wide, like `audit_sink_state`: no tenant owns a master key, so
-- there is no `tenant_id` and no row-level security. Rows are never updated;
-- losing one (or the backend key behind it) loses every secret still under
-- that generation, so nothing in rIDM deletes them.
CREATE TABLE master_key_generations (
    version     integer     PRIMARY KEY CHECK (version > 0),
    -- `pkcs11`, `aws-kms`, `vault`, `gcp-kms` or `azure-key-vault`.
    backend     text        NOT NULL CHECK (length(backend) BETWEEN 1 AND 32),
    -- The backend key that wrapped it: an ARN, a PKCS#11 label, a Transit key,
    -- a Cloud KMS key name, a Key Vault key id.
    key_ref     text        NOT NULL CHECK (length(key_ref) BETWEEN 1 AND 2048),
    wrapped_key bytea       NOT NULL CHECK (length(wrapped_key) BETWEEN 1 AND 8192),
    created_at  timestamptz NOT NULL DEFAULT now()
);
