-- Let the audit retention job drop whole monthly partitions.
--
-- Retention deleted old audit rows one batch at a time, so the monthly
-- partitions they lived in stayed forever, each with its indexes, and every
-- query across the chain still visited them. Once a month is older than
-- every tenant's retention in this database, all its rows would be purged
-- anyway: the job drops the partition instead (`audit_drop_partitions_before`),
-- and row deletes are left for tenants with a shorter retention.
--
-- Only a partition whose every chain is one the caller vouches for goes:
-- rows of chains outside `chains` (a deleted tenant's trail, which no
-- retention governs) keep their partition, and the row purge carries on for
-- the rest as before. A partition's chains are found with one index probe
-- each (a loose scan of the (chain_id, seq) index), not by reading its rows.
--
-- The partitions belong to the role that runs migrations, so the function runs
-- with its owner's rights (like `audit_ensure_partitions`), with a pinned
-- search_path, and only roles allowed to delete audit rows may call it: it
-- does nothing they could not do with DELETE. It never drops the current
-- month or a later one, nor the default partition, and it takes each
-- partition's lock for at most 5 seconds: one it cannot get is left for the
-- next run rather than queueing every audit query behind it.
CREATE OR REPLACE FUNCTION audit_drop_partitions_before(cutoff date, chains uuid[]) RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    part record;
    upper_bound date;
    foreign_chains bigint;
    dropped integer := 0;
    this_month date := date_trunc('month', now())::date;
BEGIN
    FOR part IN
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'public.audit_events'::regclass
          AND c.relname ~ '^audit_events_[0-9]{6}$'
        ORDER BY c.relname
    LOOP
        upper_bound := (to_date(substr(part.relname, 14), 'YYYYMM') + interval '1 month')::date;
        CONTINUE WHEN upper_bound > cutoff OR upper_bound > this_month;
        EXECUTE format(
            'WITH RECURSIVE c AS ( '
            '  (SELECT chain_id AS id FROM public.%1$I ORDER BY chain_id LIMIT 1) '
            '  UNION ALL '
            '  SELECT (SELECT chain_id FROM public.%1$I WHERE chain_id > c.id ORDER BY chain_id LIMIT 1) '
            '  FROM c WHERE c.id IS NOT NULL) '
            'SELECT count(*) FROM c WHERE id IS NOT NULL AND NOT (id = ANY($1))',
            part.relname)
        INTO foreign_chains USING chains;
        CONTINUE WHEN foreign_chains > 0;
        BEGIN
            SET LOCAL lock_timeout = '5s';
            EXECUTE format('ALTER TABLE public.audit_events DETACH PARTITION public.%I', part.relname);
            EXECUTE format('DROP TABLE public.%I', part.relname);
            dropped := dropped + 1;
        EXCEPTION WHEN lock_not_available THEN
            RAISE NOTICE 'audit_drop_partitions_before: % is busy; left for the next run', part.relname;
        END;
    END LOOP;
    RETURN dropped;
END;
$$;

REVOKE ALL ON FUNCTION audit_drop_partitions_before(date, uuid[]) FROM PUBLIC;
DO $$
DECLARE
    grantee_name text;
BEGIN
    FOR grantee_name IN
        SELECT DISTINCT a.grantee::regrole::text
        FROM pg_class c, aclexplode(c.relacl) a
        WHERE c.oid = 'public.audit_events'::regclass
          AND a.privilege_type = 'DELETE'
          AND a.grantee <> 0
          AND a.grantee <> c.relowner
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION audit_drop_partitions_before(date, uuid[]) TO %s', grantee_name);
    END LOOP;
END;
$$;
