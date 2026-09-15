"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { Field, SaveIndicator, Section, SelectInput, TagsInput, TextInput, Toggle } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { href, type Scope } from "@/lib/console/access";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { STANDARD_SCOPES } from "@/lib/console/clients";
import { useResourceServers, useScopes } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "./common";

export function ScopesPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { can } = useConsole();
  const scopes = useScopes(tenant);
  const [creating, setCreating] = useState(false);
  return (
    <>
      <PageHeader
        title="Scopes"
        sub="What clients may ask for; the description is what users see on the consent page."
        actions={
          can("ridm:scopes:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New scope
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Scopes">
            {scopes.isPending ? (
              <Spinner label="Loading…" />
            ) : scopes.isError ? (
              <ErrorLine error={scopes.error} />
            ) : (
              <ul className="flex flex-col gap-0.5">
                {[...scopes.data]
                  .sort((a, b) => a.name.localeCompare(b.name))
                  .map((s) => (
                    <li key={s.id}>
                      <Link
                        href={href("scopes", tenant, { scope: s.id })}
                        aria-current={s.id === selected ? "page" : undefined}
                        className={`flex items-center justify-between gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${s.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                      >
                        <span className="truncate font-mono text-[0.8125rem]">{s.name}</span>
                        {s.is_default && <Badge tone="accent">default</Badge>}
                      </Link>
                    </li>
                  ))}
              </ul>
            )}
          </Card>
        }
        detail={selected ? <ScopeView tenant={tenant} id={selected} /> : <p className="text-[0.9rem] text-muted">Choose a scope.</p>}
      />
      <CreateScope tenant={tenant} open={creating} onOpenChange={setCreating} />
    </>
  );
}

function CreateScope({ tenant, open, onOpenChange }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/scopes", { params: { path: { slug: tenant } }, body: { name: name.trim(), description: description.trim() || null, claims: [], is_default: false, resource_server_id: null } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (s) => {
      void qc.invalidateQueries({ queryKey: ["scopes", tenant] });
      setName("");
      setDescription("");
      onOpenChange(false);
      router.push(href("scopes", tenant, { scope: s.id }));
    },
  });
  return (
    <CreateDialog open={open} onOpenChange={onOpenChange} title="New scope" submitLabel="Create scope" pending={create.isPending} error={create.error?.message ?? null} onSubmit={() => name.trim() && create.mutate()}>
      <Field label="Name" hint="Cannot change later.">{(id, by) => <TextInput id={id} aria-describedby={by} value={name} onChange={(e) => setName(e.target.value)} autoFocus required placeholder="orders:read" spellCheck={false} />}</Field>
      <Field label="Description" hint="Shown to users on the consent page.">{(id, by) => <TextInput id={id} aria-describedby={by} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Read your orders" />}</Field>
    </CreateDialog>
  );
}

function ScopeView({ tenant, id }: { tenant: string; id: string }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const servers = useResourceServers(tenant);
  const query = useQuery({
    queryKey: ["scope", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/scopes/{scope}", { params: { path: { slug: tenant, scope: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<Scope | null>(null);
  const [seenId, setSeenId] = useState(id);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenId !== id) {
    setSeenId(id);
    setDraft(null);
  }
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);
  const editable = can("ridm:scopes:write");
  const save = useCallback(
    async (patch: Partial<Scope>, { keepalive }: SaveOptions) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/scopes/{scope}", { params: { path: { slug: tenant, scope: id } }, body: patch as never, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["scope", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["scope", tenant, id], data);
      void qc.invalidateQueries({ queryKey: ["scopes", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save);
  const update = (patch: Partial<Scope>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
    if (editable) queue(patch);
  };
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/scopes/{scope}", { params: { path: { slug: tenant, scope: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scopes", tenant] });
      router.push(href("scopes", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading…" />;
  const standard = STANDARD_SCOPES.includes(draft.name);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="font-mono text-[1.125rem] font-semibold text-ink">
          {draft.name} {standard && <Badge>standard</Badge>}
        </h2>
        <SaveIndicator status={status} error={error} />
      </div>
      <Section id="scope" title="Scope" description={standard ? "Standard scopes can be tuned but not deleted." : undefined}>
        <Field label="Description" hint="Shown on the consent page." wide>
          {(fid, by) => <TextInput id={fid} aria-describedby={by} value={draft.description ?? ""} disabled={!editable} onChange={(e) => update({ description: e.target.value || null })} />}
        </Field>
        <Field label="Claims" hint="Claims this scope releases in the ID token and userinfo. Enter adds one." wide>
          {(fid, by) => <TagsInput id={fid} describedBy={by} value={draft.claims} onChange={(v) => update({ claims: v })} placeholder="name, given_name" />}
        </Field>
        <Field label="Resource server" hint="Requesting this scope also targets that audience.">
          {(fid, by) => (
            <SelectInput id={fid} aria-describedby={by} value={draft.resource_server_id ?? ""} disabled={!editable} onChange={(e) => update({ resource_server_id: e.target.value || null })}>
              <option value="">None</option>
              {(servers.data ?? [])
                .filter((r) => !r.built_in)
                .map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
            </SelectInput>
          )}
        </Field>
        <div className="flex items-end">
          <div className="w-full">
            <Toggle label="Granted by default" hint="Included when a client asks for no scope." checked={draft.is_default} disabled={!editable} onChange={(v) => update({ is_default: v })} />
          </div>
        </div>
      </Section>
      {editable && !standard && <DeleteButton what="scope" pending={del.isPending} error={del.error?.message ?? null} onConfirm={() => del.mutate()} description="Clients that list this scope keep working without it." />}
    </div>
  );
}
