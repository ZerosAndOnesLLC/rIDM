-- DPoP (RFC 9449): a client may demand sender-constrained access tokens, and a
-- refresh token issued to a public client under a DPoP proof is bound to the
-- proof key's thumbprint so only that key can spend it.
ALTER TABLE clients ADD COLUMN dpop_bound_access_tokens boolean NOT NULL DEFAULT false;
ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt text;
