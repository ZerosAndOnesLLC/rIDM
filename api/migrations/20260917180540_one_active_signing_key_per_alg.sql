-- One active signing key per tenant and algorithm.
--
-- `keys::ensure_active` already expected this: it treats a conflict as "another
-- node created the key, adopt it". Without the constraint every racing creator
-- minted its own key (each with a different kid, so nothing conflicted), and a
-- tenant could end up with several active keys — tokens signed with the newest
-- while a JWKS document fetched moments earlier named another, which no relying
-- party could verify.
--
-- Existing rows first: keep the newest active key of each tenant and algorithm,
-- retire the rest with the default overlap so tokens they signed still verify.
WITH ranked AS (
    SELECT id,
           tenant_id,
           row_number() OVER (
               PARTITION BY tenant_id, alg
               ORDER BY not_before DESC, created_at DESC, id DESC
           ) AS rn
    FROM signing_keys
    WHERE status = 'active'
)
UPDATE signing_keys k
SET status = 'retiring',
    expires_at = COALESCE(k.expires_at, now() + interval '24 hours')
FROM ranked r
WHERE k.id = r.id
  AND k.tenant_id = r.tenant_id
  AND r.rn > 1;

CREATE UNIQUE INDEX signing_keys_one_active_per_alg
    ON signing_keys (tenant_id, alg)
    WHERE status = 'active';
