-- OIDC Core §5.4: when an access token is issued, the claims the `profile`,
-- `email`, `address` and `phone` scopes ask for are read from the userinfo
-- endpoint, not carried in the ID token. A client that would rather have them
-- in the ID token (no userinfo round trip) opts in.
ALTER TABLE clients ADD COLUMN id_token_scope_claims boolean NOT NULL DEFAULT false;
