"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { Field, NumberInput, SaveIndicator, Section, SelectInput, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { href, type ResourceServer, type ResourceServerDetail } from "@/lib/console/access";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useResourceServers } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { SIGNING_ALGS } from "@/lib/console/settings";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "./common";

export function ResourceServersPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { can } = useConsole();
  const servers = useResourceServers(tenant);
  const [creating, setCreating] = useState(false);
  return (
    <>
      <PageHeader
        title="Resource servers"
        sub="APIs that accept this tenant's tokens: each is an audience with its own permissions."
        actions={
          can("ridm:resource-servers:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New resource server
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Resource servers">
            {servers.isPending ? (
              <Spinner label="Loading…" />
            ) : servers.isError ? (
              <ErrorLine error={servers.error} />
            ) : (
              <ul className="flex flex-col gap-0.5">
                {servers.data.map((r) => (
                  <li key={r.id}>
                    <Link
                      href={href("resource-servers", tenant, { rs: r.id })}
                      aria-current={r.id === selected ? "page" : undefined}
                      className={`flex items-center justify-between gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${r.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                    >
                      <span className="min-w-0">
                        <span className="block truncate">{r.name}</span>
                        <span className="block truncate font-mono text-[0.75rem] text-muted">{r.identifier}</span>
                      </span>
                      {r.built_in && <Badge>built-in</Badge>}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        }
        detail={selected ? <ResourceServerView key={selected} tenant={tenant} id={selected} /> : <p className="text-[0.9rem] text-muted">Choose a resource server.</p>}
      />
      <CreateResourceServer tenant={tenant} open={creating} onOpenChange={setCreating} />
    </>
  );
}

function CreateResourceServer({ tenant, open, onOpenChange }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [name, setName] = useState("");
  const [identifier, setIdentifier] = useState("");
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/resource-servers", { params: { path: { slug: tenant } }, body: { name: name.trim(), identifier: identifier.trim(), token_ttl_secs: null, signing_alg: null, allow_offline_access: null } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["resource-servers", tenant] });
      setName("");
      setIdentifier("");
      onOpenChange(false);
      router.push(href("resource-servers", tenant, { rs: r.id }));
    },
  });
  return (
    <CreateDialog open={open} onOpenChange={onOpenChange} title="New resource server" submitLabel="Create" pending={create.isPending} error={create.error?.message ?? null} onSubmit={() => name.trim() && identifier.trim() && create.mutate()}>
      <Field label="Name">{(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus required placeholder="Orders API" />}</Field>
      <Field label="Identifier" hint="The audience (`aud`) value tokens carry; usually a URL or URN. Cannot change later.">
        {(id, by) => <TextInput id={id} aria-describedby={by} value={identifier} onChange={(e) => setIdentifier(e.target.value)} required placeholder="https://api.example.com/orders" spellCheck={false} />}
      </Field>
    </CreateDialog>
  );
}

function ResourceServerView({ tenant, id }: { tenant: string; id: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const query = useQuery({
    queryKey: ["resource-server", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/resource-servers/{rs}", { params: { path: { slug: tenant, rs: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<ResourceServerDetail | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);
  const editable = can("ridm:resource-servers:write") && !(draft?.built_in ?? false);
  const save = useCallback(
    async (patch: Partial<ResourceServer>, { keepalive }: SaveOptions) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/resource-servers/{rs}", { params: { path: { slug: tenant, rs: id } }, body: patch as never, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["resource-server", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["resource-server", tenant, id], (old: ResourceServerDetail | undefined) => (old ? { ...old, ...data } : old));
      void qc.invalidateQueries({ queryKey: ["resource-servers", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save, { baseline: query.data });
  const update = (patch: Partial<ResourceServer>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
    if (editable) queue(patch);
  };
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/resource-servers/{rs}", { params: { path: { slug: tenant, rs: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["resource-servers", tenant] });
      router.push(href("resource-servers", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading…" />;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">
          {draft.name} {draft.built_in && <Badge>built-in</Badge>}
        </h2>
        <SaveIndicator status={status} error={error} />
      </div>
      <Section id="rs" title="Resource server" description={draft.built_in ? "The admin API's own resource server is read-only." : "Tokens requested for this audience carry its permissions."}>
        <Field label="Name">{(fid) => <TextInput id={fid} value={draft.name} disabled={!editable} onChange={(e) => update({ name: e.target.value })} />}</Field>
        <Field label="Identifier (audience)">{(fid) => <TextInput id={fid} value={draft.identifier} readOnly disabled className="font-mono" />}</Field>
        <Field label="Token lifetime" hint="Caps the access token lifetime for this audience; empty = client or tenant default.">
          {(fid, by) => <NumberInput id={fid} describedBy={by} value={draft.token_ttl_secs ?? null} min={30} nullable onValue={(v) => update({ token_ttl_secs: v })} unit="s" />}
        </Field>
        <Field label="Signing algorithm" hint="Access tokens for this audience are signed with the tenant's active key of this algorithm (created if there is none). Empty = the tenant's default algorithm.">
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={draft.signing_alg ?? ""} disabled={!editable} onChange={(e) => update({ signing_alg: e.target.value || null })}>
              <option value="">Tenant default</option>
              {SIGNING_ALGS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
        <div className="sm:col-span-2">
          <Toggle label="Allow offline access" hint="Tokens for this audience may carry offline_access: refresh tokens that outlive the sign-in session. Off, refresh tokens end with the session." checked={draft.allow_offline_access} disabled={!editable} onChange={(v) => update({ allow_offline_access: v })} />
        </div>
      </Section>
      <Permissions tenant={tenant} rs={draft} editable={can("ridm:resource-servers:write") && !draft.built_in} onChanged={() => void qc.invalidateQueries({ queryKey: ["resource-server", tenant, id] }).then(() => setResetCount((n) => n + 1))} />
      {can("ridm:resource-servers:write") && !draft.built_in && <DeleteButton what="resource server" pending={del.isPending} error={del.error?.message ?? null} onConfirm={() => del.mutate()} description="Its permissions are removed from every role; clients allowed this audience lose it." />}
    </div>
  );
}

function Permissions({ tenant, rs, editable, onChanged }: { tenant: string; rs: ResourceServerDetail; editable: boolean; onChanged: () => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const add = useMutation({
    mutationFn: async () => {
      const { error } = await client.POST("/admin/tenants/{slug}/resource-servers/{rs}/permissions", { params: { path: { slug: tenant, rs: rs.id } }, body: { name: name.trim(), description: description.trim() || null } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      setName("");
      setDescription("");
      void qc.invalidateQueries({ queryKey: ["permissions", tenant] });
      onChanged();
    },
  });
  const remove = useMutation({
    mutationFn: async (pid: string) => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/resource-servers/{rs}/permissions/{permission_id}", { params: { path: { slug: tenant, rs: rs.id, permission_id: pid } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["permissions", tenant] });
      onChanged();
    },
  });
  return (
    <Card title="Permissions">
      <p className="mb-2 text-[0.8125rem] text-muted">Named permissions roles can be granted; they appear in the token&apos;s permissions claim.</p>
      {rs.permissions.length === 0 && <p className="text-[0.875rem] text-muted">None yet.</p>}
      <ul className="divide-y divide-line">
        {rs.permissions.map((p) => (
          <li key={p.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
            <span>
              <span className="font-mono text-[0.8125rem] font-medium text-ink">{p.name}</span>
              {p.description && <span className="ms-2 text-muted">{p.description}</span>}
            </span>
            {editable && (
              <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={remove.isPending} onClick={() => remove.mutate(p.id)}>
                Remove
              </Button>
            )}
          </li>
        ))}
      </ul>
      {editable && (
        <form
          className="mt-3 flex flex-wrap gap-2 border-t border-line pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim()) add.mutate();
          }}
        >
          <TextInput aria-label="Permission name" value={name} onChange={(e) => setName(e.target.value)} placeholder="orders:read" spellCheck={false} className="max-w-[14rem]" />
          <TextInput aria-label="Permission description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description" className="min-w-[12rem] flex-1" />
          <Button type="submit" variant="primary" disabled={!name.trim() || add.isPending}>
            Add
          </Button>
        </form>
      )}
      <ErrorLine error={add.error ?? remove.error} />
    </Card>
  );
}
