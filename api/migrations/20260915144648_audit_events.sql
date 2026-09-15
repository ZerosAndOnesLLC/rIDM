-- 0015: audit log. One row per domain event, partitioned by month, chained
-- per tenant with SHA-256 so tampering or deletion inside the retained
-- window is detectable. Global events (no tenant) form their own chain and
-- are visible only with the RLS bypass.

CREATE TABLE audit_events (
    id            uuid        NOT NULL,
    tenant_id     uuid,
    -- tenant_id, or the nil uuid for the global chain
    chain_id      uuid        NOT NULL,
    seq           bigint      NOT NULL,
    occurred_at   timestamptz NOT NULL,
    recorded_at   timestamptz NOT NULL DEFAULT now(),
    name          text        NOT NULL,
    actor_type    text        NOT NULL,
    actor_id      uuid,
    subject_id    uuid,
    ip            text,
    user_agent    text,
    payload       jsonb       NOT NULL,
    prev_hash     bytea,
    hash          bytea       NOT NULL,
    PRIMARY KEY (id, occurred_at),
    CONSTRAINT audit_events_actor_type_check CHECK (actor_type IN ('user', 'client', 'admin', 'system'))
) PARTITION BY RANGE (occurred_at);

CREATE INDEX audit_events_chain_seq_idx ON audit_events (chain_id, seq);
CREATE INDEX audit_events_tenant_time_idx ON audit_events (tenant_id, occurred_at, id);
CREATE INDEX audit_events_tenant_name_idx ON audit_events (tenant_id, name, occurred_at);
CREATE INDEX audit_events_tenant_actor_idx ON audit_events (tenant_id, actor_id, occurred_at) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_events_tenant_subject_idx ON audit_events (tenant_id, subject_id, occurred_at) WHERE subject_id IS NOT NULL;

-- Rows with no tenant are reachable only through the bypass.
SELECT enable_tenant_rls('audit_events');

-- Anything outside a monthly partition lands here rather than failing.
CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;

-- Monthly partitions from the current month through `months_ahead`.
CREATE OR REPLACE FUNCTION audit_ensure_partitions(months_ahead integer) RETURNS integer
LANGUAGE plpgsql AS $$
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
        IF to_regclass(part) IS NULL THEN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',
                part, from_date, to_date);
            created := created + 1;
        END IF;
    END LOOP;
    RETURN created;
END;
$$;

SELECT audit_ensure_partitions(2);

