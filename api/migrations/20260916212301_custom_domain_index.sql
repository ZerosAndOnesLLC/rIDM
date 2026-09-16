-- A custom domain (settings.custom_domain) maps a request host to one tenant,
-- so it must be unique across tenants; the resolver looks it up by this index.
CREATE UNIQUE INDEX tenants_custom_domain_key
    ON tenants ((lower(settings->>'custom_domain')))
    WHERE settings->>'custom_domain' IS NOT NULL;
