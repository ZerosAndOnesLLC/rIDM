-- The ID token minted from a refresh token must repeat the original
-- authentication context (OIDC Core §12.2: same `auth_time`, and the `acr`
-- and `amr` the session was established with), so the family carries it.
ALTER TABLE refresh_tokens
    ADD COLUMN auth_time timestamptz,
    ADD COLUMN amr text[] NOT NULL DEFAULT '{}',
    ADD COLUMN acr text;
