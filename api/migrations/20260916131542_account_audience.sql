-- Account audience.
--
-- Every tenant gets a built-in resource server `urn:ridm:account`: the
-- audience the bundled account console's tokens carry, which the self-service
-- `/t/{slug}/account/...` API requires. It has no permissions: the token's
-- subject may only act on their own account.

SELECT set_config('app.bypass_rls', 'on', true);

CREATE OR REPLACE FUNCTION seed_account_model(p_tenant_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    previous text := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', 'on', true);
    INSERT INTO resource_servers (tenant_id, identifier, name, allow_offline_access, built_in)
    VALUES (p_tenant_id, 'urn:ridm:account', 'rIDM account API', true, true)
    ON CONFLICT (tenant_id, identifier) DO UPDATE SET built_in = true;
    PERFORM set_config('app.bypass_rls', coalesce(previous, 'off'), true);
END;
$$;

CREATE OR REPLACE FUNCTION tenants_seed_account_model_trigger() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM seed_account_model(NEW.id);
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenants_seed_account_model AFTER INSERT ON tenants
    FOR EACH ROW EXECUTE FUNCTION tenants_seed_account_model_trigger();

-- Backfill tenants created before this migration.
SELECT seed_account_model(id) FROM tenants;
