-- no-transaction
-- Tenant discovery by e-mail domain (`settings->'discovery'->'email_domains' ? $1`).
CREATE INDEX CONCURRENTLY IF NOT EXISTS tenants_email_domains_idx
    ON tenants USING gin ((settings->'discovery'->'email_domains'));
