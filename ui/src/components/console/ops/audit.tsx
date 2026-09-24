"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { Download, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Field, SelectInput, TextInput } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { EVENT_NAMES, downloadWithToken, toRfc3339, type AuditEvent } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "../access/common";

interface Filter {
  from: string;
  to: string;
  name: string;
  actor_id: string;
  subject_id: string;
  user_id: string;
}
const EMPTY: Filter = { from: "", to: "", name: "", actor_id: "", subject_id: "", user_id: "" };

/** The tenant's audit trail (or the global chain) with filters, export and chain verification. */
export function AuditPage({ tenant }: { tenant: string }) {
  const { client, me } = useConsole();
  const [scope, setScope] = useState<"tenant" | "global">("tenant");
  const [draft, setDraft] = useState<Filter>(EMPTY);
  const [filter, setFilter] = useState<Filter>(EMPTY);
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [open, setOpen] = useState<string | null>(null);
  const cursor = cursors[cursors.length - 1];
  const query = { from: toRfc3339(filter.from), to: toRfc3339(filter.to), name: filter.name || undefined, actor_id: filter.actor_id || undefined, subject_id: filter.subject_id || undefined, user_id: filter.user_id || undefined };
  const page = useQuery({
    queryKey: ["audit", scope, tenant, filter, cursor],
    queryFn: async () => {
      const r = scope === "global" ? await client.GET("/admin/audit", { params: { query: { ...query, cursor, limit: 50 } } }) : await client.GET("/admin/tenants/{slug}/audit", { params: { path: { slug: tenant }, query: { ...query, cursor, limit: 50 } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
      return r.data;
    },
  });
  const verify = useMutation({
    mutationFn: async () => {
      const r = scope === "global" ? await client.GET("/admin/audit/verify") : await client.GET("/admin/tenants/{slug}/audit/verify", { params: { path: { slug: tenant } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
      return r.data;
    },
  });
  const exp = useMutation({
    mutationFn: async (format: "json" | "csv") => {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) if (v) q.set(k, v);
      q.set("format", format);
      const path = scope === "global" ? `/admin/audit/export?${q}` : `/admin/tenants/${encodeURIComponent(tenant)}/audit/export?${q}`;
      await downloadWithToken(path);
    },
  });
  const apply = () => {
    setFilter(draft);
    setCursors([undefined]);
  };

  return (
    <>
      <PageHeader
        title="Audit log"
        sub="Every recorded event, hash-chained so tampering shows."
        actions={
          <>
            <Button disabled={exp.isPending} onClick={() => exp.mutate("json")}>
              <Download className="size-4" aria-hidden />
              JSON
            </Button>
            <Button disabled={exp.isPending} onClick={() => exp.mutate("csv")}>
              <Download className="size-4" aria-hidden />
              CSV
            </Button>
            <Button disabled={verify.isPending} onClick={() => verify.mutate()}>
              <ShieldCheck className="size-4" aria-hidden />
              Verify chain
            </Button>
          </>
        }
      />
      <ErrorLine error={exp.error ?? verify.error} />
      {verify.data && (
        <p role="status" className={`mb-4 rounded-[var(--radius)] px-4 py-2.5 text-[0.875rem] ${verify.data.valid ? "bg-ok-soft text-ok" : "bg-danger-soft text-danger"}`}>
          {verify.data.valid ? `Chain intact: ${verify.data.checked} rows checked (${verify.data.first_seq ?? "—"} → ${verify.data.last_seq ?? "—"}).` : `Chain broken at position ${verify.data.broken_at_seq}: ${verify.data.reason ?? "hash mismatch"}.`}
        </p>
      )}
      <form
        className="mb-4 grid gap-3 rounded-[calc(var(--radius)+2px)] border border-line bg-paper p-4 sm:grid-cols-2 lg:grid-cols-4"
        onSubmit={(e) => {
          e.preventDefault();
          apply();
        }}
      >
        {me?.scope === "global" && (
          <Field label="Chain">
            {(id) => (
              <SelectInput
                id={id}
                value={scope}
                onChange={(e) => {
                  setScope(e.target.value as "tenant" | "global");
                  setCursors([undefined]);
                }}
              >
                <option value="tenant">This tenant</option>
                <option value="global">Global (cross-tenant events)</option>
              </SelectInput>
            )}
          </Field>
        )}
        <Field label="Event">
          {(id) => (
            <SelectInput id={id} value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })}>
              <option value="">Any event</option>
              {EVENT_NAMES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
        <Field label="From">{(id) => <TextInput id={id} type="datetime-local" value={draft.from} onChange={(e) => setDraft({ ...draft, from: e.target.value })} />}</Field>
        <Field label="To">{(id) => <TextInput id={id} type="datetime-local" value={draft.to} onChange={(e) => setDraft({ ...draft, to: e.target.value })} />}</Field>
        <Field label="Actor ID">{(id) => <TextInput id={id} value={draft.actor_id} onChange={(e) => setDraft({ ...draft, actor_id: e.target.value.trim() })} placeholder="uuid" spellCheck={false} />}</Field>
        <Field label="Subject ID">{(id) => <TextInput id={id} value={draft.subject_id} onChange={(e) => setDraft({ ...draft, subject_id: e.target.value.trim() })} placeholder="uuid" spellCheck={false} />}</Field>
        <Field label="User ID">{(id) => <TextInput id={id} value={draft.user_id} onChange={(e) => setDraft({ ...draft, user_id: e.target.value.trim() })} placeholder="uuid" spellCheck={false} />}</Field>
        <div className="flex items-end gap-2">
          <Button type="submit" variant="primary">
            Apply filters
          </Button>
          <Button
            onClick={() => {
              setDraft(EMPTY);
              setFilter(EMPTY);
              setCursors([undefined]);
            }}
          >
            Clear
          </Button>
        </div>
      </form>
      <Card title="Events">
        {page.isPending ? (
          <Spinner label="Loading…" />
        ) : page.isError ? (
          <ErrorLine error={page.error} />
        ) : page.data.items.length === 0 ? (
          <p className="text-[0.875rem] text-muted">No events match.</p>
        ) : (
          <ul className="divide-y divide-line">
            {page.data.items.map((e) => (
              <EventRow key={e.id} e={e} open={open === e.id} onToggle={() => setOpen(open === e.id ? null : e.id)} />
            ))}
          </ul>
        )}
        <div className="mt-3 flex justify-between">
          <Button disabled={cursors.length <= 1} onClick={() => setCursors((c) => c.slice(0, -1))}>
            Newer
          </Button>
          <Button disabled={!page.data?.next_cursor} onClick={() => setCursors((c) => [...c, page.data?.next_cursor ?? undefined])}>
            Older
          </Button>
        </div>
      </Card>
    </>
  );
}

function EventRow({ e, open, onToggle }: { e: AuditEvent; open: boolean; onToggle: () => void }) {
  return (
    <li className="py-2 text-[0.875rem]">
      <button type="button" onClick={onToggle} aria-expanded={open} className="flex w-full flex-wrap items-center justify-between gap-2 text-start">
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="font-mono text-[0.8125rem] font-medium text-ink">{e.name}</span>
          <Badge>{e.actor_type}</Badge>
          {e.ip && <span className="text-[0.8125rem] text-muted">{e.ip}</span>}
        </span>
        <span className="text-[0.8125rem] text-muted">
          #{e.seq} · {formatDate("en", e.occurred_at)}
        </span>
      </button>
      {open && (
        <pre tabIndex={0} aria-label="Event details" className="mt-2 max-h-72 overflow-auto rounded-[var(--radius)] bg-ground px-3 py-2 font-mono text-[0.75rem] text-ink">
          {JSON.stringify({ id: e.id, actor_id: e.actor_id, subject_id: e.subject_id, user_agent: e.user_agent, payload: e.payload, hash: e.hash, prev_hash: e.prev_hash }, null, 2)}
        </pre>
      )}
    </li>
  );
}
