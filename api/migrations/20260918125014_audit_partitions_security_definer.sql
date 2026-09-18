-- Let the application role create audit partitions.
--
-- The `audit_retention` job calls `audit_ensure_partitions` as the API's role,
-- which is DML only (no CREATE on the schema) in the recommended two-role
-- layout. Once the partitions made when the migration ran were used up, the
-- job failed on every run: new rows fell into `audit_events_default` and the
-- retention purge after it never ran. The function now runs with its owner's
-- rights (the role that runs migrations and owns `audit_events`), with a
-- pinned search_path so a caller cannot shadow what it refers to, and only
-- roles allowed to write audit rows may call it.
--
-- A month whose range already has rows in the default partition (written
-- while partitions were missing) is skipped instead of failing the whole call:
-- Postgres refuses such a partition, the rows stay where they are, and the
-- purge (a plain DELETE through the parent) still reaches them. The purge
-- needs no DDL, so it needs no such change.
CREATE OR REPLACE FUNCTION audit_ensure_partitions(months_ahead integer) RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    start_month date := date_trunc('month', now())::date;
    m integer;
    from_date date;
    to_date date;
    part text;
    created integer := 0;
BEGIN
    FOR m IN 0..months_ahead LOOP
        from_date := (start_month + (m || ' month')::interval)::date;
        to_date := (from_date + interval '1 month')::date;
        part := 'audit_events_' || to_char(from_date, 'YYYYMM');
        CONTINUE WHEN to_regclass(format('public.%I', part)) IS NOT NULL;
        IF EXISTS (
            SELECT 1 FROM public.audit_events_default
            WHERE occurred_at >= from_date AND occurred_at < to_date
        ) THEN
            RAISE NOTICE 'audit_ensure_partitions: % has rows in audit_events_default; skipped', part;
            CONTINUE;
        END IF;
        BEGIN
            EXECUTE format(
                'CREATE TABLE public.%I PARTITION OF public.audit_events FOR VALUES FROM (%L) TO (%L)',
                part, from_date, to_date);
            created := created + 1;
        EXCEPTION WHEN duplicate_table THEN
            -- Another node created it first.
            NULL;
        END;
    END LOOP;
    RETURN created;
END;
$$;

-- Callable by the roles that write audit rows, not by everyone. The
-- application role is whatever the deployment named it; it is the role the
-- migrating role granted INSERT on `audit_events` (through its default
-- privileges, see deploy/postgres/init-app-role.sh).
REVOKE ALL ON FUNCTION audit_ensure_partitions(integer) FROM PUBLIC;
DO $$
DECLARE
    grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT a.grantee::regrole::text
        FROM pg_class c, aclexplode(c.relacl) a
        WHERE c.oid = 'public.audit_events'::regclass
          AND a.privilege_type = 'INSERT'
          AND a.grantee <> 0
          AND a.grantee <> c.relowner
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION audit_ensure_partitions(integer) TO %s', grantee_name);
    END LOOP;
END;
$$;
