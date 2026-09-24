"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, RotateCw, Send } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { Field, NumberInput, SaveIndicator, Section, SelectInput, TagsInput, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { EVENT_NAMES, EVENT_PREFIXES, href, type Webhook, type WebhookDelivery } from "@/lib/console/ops";
import { useConsole } from "@/lib/console/session";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "../access/common";
import { RevealModal, type Revealed } from "../clients/reveal";
import { JsonInput } from "../users/attributes";

const TONE: Record<WebhookDelivery["status"], "ok" | "accent" | "neutral" | "danger"> = { delivered: "ok", pending: "accent", sending: "accent", failed: "neutral", dead: "danger" };

export function WebhooksPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { client, can } = useConsole();
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const hooks = useQuery({
    queryKey: ["webhooks", tenant],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/webhooks", { params: { path: { slug: tenant } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  return (
    <>
      <PageHeader
        title="Webhooks"
        sub="Signed HTTP deliveries of the tenant's events, retried with backoff."
        actions={
          can("ridm:webhooks:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New webhook
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Webhooks">
            {hooks.isPending ? (
              <Spinner label="Loading…" />
            ) : hooks.isError ? (
              <ErrorLine error={hooks.error} />
            ) : hooks.data.length === 0 ? (
              <p className="text-[0.875rem] text-muted">No webhooks yet.</p>
            ) : (
              <ul className="flex flex-col gap-0.5">
                {hooks.data.map((w) => (
                  <li key={w.id}>
                    <Link
                      href={href("webhooks", tenant, { webhook: w.id })}
                      aria-current={w.id === selected ? "page" : undefined}
                      className={`flex items-center justify-between gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${w.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                    >
                      <span className="min-w-0">
                        <span className="block truncate">{w.name}</span>
                        <span className="block truncate text-[0.75rem] text-muted">{w.url}</span>
                      </span>
                      {!w.enabled && <Badge>off</Badge>}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        }
        detail={selected ? <WebhookView key={selected} tenant={tenant} id={selected} onReveal={setRevealed} /> : <p className="text-[0.9rem] text-muted">Choose a webhook.</p>}
      />
      <CreateWebhook tenant={tenant} open={creating} onOpenChange={setCreating} onReveal={setRevealed} />
      <RevealModal revealed={revealed} onClose={() => setRevealed(null)} />
    </>
  );
}

function EventsField({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  return (
    <Field label="Events" hint="Exact names, prefixes like user.*, or * for everything. Enter adds one." wide>
      {(id, by) => (
        <>
          <TagsInput id={id} describedBy={by} value={value} onChange={onChange} placeholder="user.created, login.*" />
          <datalist id={`${id}-list`}>
            {["*", ...EVENT_PREFIXES, ...EVENT_NAMES].map((n) => (
              <option key={n} value={n} />
            ))}
          </datalist>
        </>
      )}
    </Field>
  );
}

function CreateWebhook({ tenant, open, onOpenChange, onReveal }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void; onReveal: (r: Revealed) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<string[]>(["*"]);
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/webhooks", { params: { path: { slug: tenant } }, body: { name: name.trim(), url: url.trim(), events, enabled: true, headers: null, max_attempts: null } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (w) => {
      void qc.invalidateQueries({ queryKey: ["webhooks", tenant] });
      setName("");
      setUrl("");
      onOpenChange(false);
      onReveal({ title: `${w.name} created`, description: "Verify deliveries with this signing secret (X-RIDM-Signature, HMAC-SHA256).", values: [{ label: "Signing secret", value: w.secret }] });
      router.push(href("webhooks", tenant, { webhook: w.id }));
    },
  });
  return (
    <CreateDialog open={open} onOpenChange={onOpenChange} title="New webhook" submitLabel="Create webhook" pending={create.isPending} error={create.error?.message ?? null} onSubmit={() => name.trim() && url.trim() && create.mutate()}>
      <Field label="Name">{(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus required placeholder="CRM sync" />}</Field>
      <Field label="URL" hint="Receives POST with a JSON body {delivery_id, attempt, event}.">
        {(id, by) => <TextInput id={id} aria-describedby={by} type="url" value={url} onChange={(e) => setUrl(e.target.value)} required placeholder="https://hooks.example.com/ridm" spellCheck={false} />}
      </Field>
      <EventsField value={events} onChange={setEvents} />
    </CreateDialog>
  );
}

function WebhookView({ tenant, id, onReveal }: { tenant: string; id: string; onReveal: (r: Revealed) => void }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const editable = can("ridm:webhooks:write");
  const query = useQuery({
    queryKey: ["webhook", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/webhooks/{webhook}", { params: { path: { slug: tenant, webhook: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<Webhook | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);
  const save = useCallback(
    async (patch: Partial<Webhook>, { keepalive }: SaveOptions) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/webhooks/{webhook}", { params: { path: { slug: tenant, webhook: id } }, body: patch as never, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["webhook", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["webhook", tenant, id], data);
      void qc.invalidateQueries({ queryKey: ["webhooks", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save, { baseline: query.data });
  const update = (patch: Partial<Webhook>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
    if (editable) queue(patch);
  };
  const rotate = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/webhooks/{webhook}/secret", { params: { path: { slug: tenant, webhook: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (w) => onReveal({ title: "New signing secret", description: "Deliveries from now on are signed with it.", values: [{ label: "Signing secret", value: w.secret }] }),
  });
  const test = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/webhooks/{webhook}/test", { params: { path: { slug: tenant, webhook: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["webhook", tenant, id, "deliveries"] }),
  });
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/webhooks/{webhook}", { params: { path: { slug: tenant, webhook: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["webhooks", tenant] });
      router.push(href("webhooks", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading…" />;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">{draft.name}</h2>
        <span className="flex flex-wrap items-center gap-2">
          <SaveIndicator status={status} error={error} />
          {editable && (
            <>
              <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={test.isPending} onClick={() => test.mutate()}>
                <Send className="size-3.5" aria-hidden />
                Send test ping
              </Button>
              <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={rotate.isPending} onClick={() => rotate.mutate()}>
                <RotateCw className="size-3.5" aria-hidden />
                Rotate secret
              </Button>
            </>
          )}
        </span>
      </div>
      <ErrorLine error={test.error ?? rotate.error} />
      {test.data && (
        <p role="status" className="text-[0.8125rem] text-muted">
          Test delivery queued: {test.data.status} (attempt {test.data.attempts} of {test.data.max_attempts}).
        </p>
      )}
      <Section id="webhook" title="Endpoint">
        <Field label="Name">{(fid) => <TextInput id={fid} value={draft.name} disabled={!editable} onChange={(e) => update({ name: e.target.value })} />}</Field>
        <Field label="URL">{(fid) => <TextInput id={fid} type="url" value={draft.url} disabled={!editable} spellCheck={false} onChange={(e) => update({ url: e.target.value })} />}</Field>
        <div className="sm:col-span-2">
          <Toggle label="Enabled" hint="Disabled webhooks receive nothing; pending deliveries wait." checked={draft.enabled} disabled={!editable} onChange={(v) => update({ enabled: v })} />
        </div>
        <EventsField value={draft.events} onChange={(v) => update({ events: v })} />
        <Field label="Maximum attempts" hint="Retries on 5xx, 408, 425, 429 and network errors with backoff.">
          {(fid, by) => <NumberInput id={fid} describedBy={by} value={draft.max_attempts} min={1} max={20} onValue={(v) => v !== null && update({ max_attempts: v })} />}
        </Field>
        <Field label="Static headers" hint="JSON object sent with every delivery (an Authorization header, say)." wide>
          {(fid, by) => <JsonInput id={fid} describedBy={by} value={draft.headers && Object.keys(draft.headers as object).length ? draft.headers : null} disabled={!editable} onChange={(v) => update({ headers: v ?? {} })} />}
        </Field>
      </Section>
      <Deliveries tenant={tenant} id={id} editable={editable} />
      {editable && <DeleteButton what="webhook" pending={del.isPending} error={del.error?.message ?? null} onConfirm={() => del.mutate()} description="Queued deliveries are dropped." />}
    </div>
  );
}

function Deliveries({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const [status, setStatus] = useState<WebhookDelivery["status"] | "">("");
  const [open, setOpen] = useState<string | null>(null);
  const list = useQuery({
    queryKey: ["webhook", tenant, id, "deliveries", status],
    // Quick while something is still on its way, slow once it all settled.
    refetchInterval: (q) => (q.state.data?.some((d) => d.status === "pending" || d.status === "failed" || d.status === "sending") ? 10_000 : 60_000),
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/webhooks/{webhook}/deliveries", { params: { path: { slug: tenant, webhook: id }, query: { status: status || undefined, limit: 50 } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const redeliver = useMutation({
    mutationFn: async (deliveryId: string) => {
      const { error } = await client.POST("/admin/tenants/{slug}/webhooks/{webhook}/deliveries/{delivery}/redeliver", { params: { path: { slug: tenant, webhook: id, delivery: deliveryId } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["webhook", tenant, id, "deliveries"] }),
  });
  const redeliverDead = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/webhooks/{webhook}/deliveries/redeliver-dead", { params: { path: { slug: tenant, webhook: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["webhook", tenant, id, "deliveries"] }),
  });
  return (
    <Card
      title="Deliveries"
      actions={
        <div className="flex flex-wrap items-center gap-2">
          {editable && (
            <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={redeliverDead.isPending} onClick={() => redeliverDead.mutate()}>
              Redeliver dead
            </Button>
          )}
          <SelectInput aria-label="Delivery status" value={status} onChange={(e) => setStatus(e.target.value as WebhookDelivery["status"] | "")} className="min-h-8 w-auto text-[0.8125rem]">
            <option value="">Any status</option>
            {(["pending", "sending", "delivered", "failed", "dead"] as const).map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </SelectInput>
        </div>
      }
    >
      <ErrorLine error={redeliver.error ?? redeliverDead.error} />
      {redeliverDead.data && (
        <p className="mb-2 text-[0.8125rem] text-muted" role="status">
          {redeliverDead.data.requeued} dead {redeliverDead.data.requeued === 1 ? "delivery" : "deliveries"} sent again.
        </p>
      )}
      {list.isPending ? (
        <Spinner label="Loading…" />
      ) : list.isError ? (
        <ErrorLine error={list.error} />
      ) : list.data.length === 0 ? (
        <p className="text-[0.875rem] text-muted">Nothing delivered yet.</p>
      ) : (
        <ul className="divide-y divide-line">
          {list.data.map((d) => (
            <li key={d.id} className="py-2 text-[0.875rem]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <button type="button" onClick={() => setOpen(open === d.id ? null : d.id)} aria-expanded={open === d.id} className="inline-flex flex-wrap items-center gap-2 text-start">
                  <span className="font-mono text-[0.8125rem] font-medium text-ink">{d.event_name}</span>
                  <Badge tone={TONE[d.status]}>{d.status}</Badge>
                  <span className="text-[0.8125rem] text-muted">
                    attempt {d.attempts}/{d.max_attempts}
                    {d.last_status ? ` · HTTP ${d.last_status}` : ""} · {formatDate("en", d.created_at)}
                  </span>
                </button>
                {editable && (d.status === "dead" || d.status === "delivered" || d.status === "failed") && (
                  <Button className="min-h-8 px-2.5 text-[0.8125rem]" disabled={redeliver.isPending} onClick={() => redeliver.mutate(d.id)}>
                    Redeliver
                  </Button>
                )}
              </div>
              {open === d.id && (
                <pre tabIndex={0} aria-label="Delivery details" className="mt-2 max-h-72 overflow-auto rounded-[var(--radius)] bg-ground px-3 py-2 font-mono text-[0.75rem] text-ink">
                  {JSON.stringify({ last_error: d.last_error, response: d.response_snippet, next_attempt_at: d.next_attempt_at, payload: d.payload }, null, 2)}
                </pre>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
