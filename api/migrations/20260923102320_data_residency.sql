-- Data residency: a tenant's data can live in a regional database.
--
-- The home database (`DATABASE_URL`) keeps the authoritative `tenants`
-- registry. A tenant whose `data_region` names a configured region has every
-- tenant-scoped row in that region's database, which runs this same schema
-- and holds a copy of the tenant's `tenants` row for the foreign keys; the
-- home database holds only the registry row. NULL: the tenant lives in the
-- home database, as every tenant did before.
--
-- `registry_only` marks the home database's row of a tenant whose data
-- lives in a region: nothing of that tenant is in this database but the
-- row. A migration that seeds something per tenant must skip those rows:
--     SELECT seed_something(id) FROM tenants WHERE NOT registry_only;
-- (a region's own copy of the row is not registry-only: its data is there).
--
-- `relocating` is set while `ridm-api move-tenant` copies a tenant between
-- databases: every node then refuses the tenant's transactions until the
-- move flips `data_region` and clears it.

ALTER TABLE tenants
    ADD COLUMN data_region   text,
    ADD COLUMN registry_only boolean NOT NULL DEFAULT false,
    ADD COLUMN relocating    boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT tenants_data_region_format
        CHECK (data_region ~ '^[a-z][a-z0-9-]{0,31}$' AND data_region <> 'home');

CREATE INDEX tenants_data_region_idx ON tenants (data_region) WHERE data_region IS NOT NULL;

-- A registry-only row must not seed the home database, and a row copied
-- into a database by a move must not seed it either: the move copies the
-- seeded rows with everything else, and sets `app.skip_tenant_seed` for it.
CREATE OR REPLACE FUNCTION tenant_seed_skipped(t tenants) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT t.registry_only
        OR COALESCE(current_setting('app.skip_tenant_seed', true), '') = 'on'
$$;

CREATE OR REPLACE FUNCTION tenants_seed_admin_model_trigger() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT tenant_seed_skipped(NEW) THEN
        PERFORM seed_admin_model(NEW.id);
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION tenants_seed_account_model_trigger() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT tenant_seed_skipped(NEW) THEN
        PERFORM seed_account_model(NEW.id);
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION tenants_seed_scopes_trigger() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT tenant_seed_skipped(NEW) THEN
        PERFORM seed_default_scopes(NEW.id);
    END IF;
    RETURN NEW;
END;
$$;
