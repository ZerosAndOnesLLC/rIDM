"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useState } from "react";
import { Field, SaveIndicator, Section, SelectInput, TextInput } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { href, type Role, type RoleDetail } from "@/lib/console/access";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useResourceServers } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { userHref } from "@/lib/console/users";
import { useRolesAndGroups } from "../users/invite";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "./common";

export function RolesPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { client, can } = useConsole();
  const { roles } = useRolesAndGroups(tenant);
  const clients = useQuery({
    queryKey: ["clients", tenant, "names"],
    staleTime: 60_000,
    queryFn: async () => {
      const names: Record<string, string> = {};
      let cursor: string | undefined;
      for (let i = 0; i < 10; i += 1) {
        const { data } = await client.GET("/admin/tenants/{slug}/clients", { params: { path: { slug: tenant }, query: { limit: 100, cursor } } });
        if (!data) break;
        for (const c of data.items) names[c.id] = c.name;
        if (!data.next_cursor) break;
        cursor = data.next_cursor;
      }
      return names;
    },
  });
  const [creating, setCreating] = useState(false);
  const [filter, setFilter] = useState("");
  const names = clients.data ?? {};
  const list = (roles.data ?? [])
    .filter((r) => !filter || r.name.toLowerCase().includes(filter.toLowerCase()))
    .sort((a, b) => (a.client_id ?? "").localeCompare(b.client_id ?? "") || a.name.localeCompare(b.name));
  return (
    <>
      <PageHeader
        title="Roles"
        sub="Realm roles and per-client roles; composites nest, permissions attach."
        actions={
          can("ridm:roles:write") ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New role
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Roles">
            <TextInput aria-label="Filter roles" placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} className="mb-3" />
            {roles.isPending ? (
              <Spinner label="Loading…" />
            ) : roles.isError ? (
              <ErrorLine error={roles.error} />
            ) : (
              <ul className="flex flex-col gap-0.5">
                {list.map((r) => (
                  <li key={r.id}>
                    <Link
                      href={href("roles", tenant, { role: r.id })}
                      aria-current={r.id === selected ? "page" : undefined}
                      className={`flex items-center justify-between gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${r.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                    >
                      <span className="truncate">
                        {r.client_id && <span className="text-muted">{names[r.client_id] ?? "client"} / </span>}
                        {r.name}
                      </span>
                      {r.built_in && <Badge>built-in</Badge>}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        }
        detail={selected ? <RoleDetailView tenant={tenant} id={selected} clientNames={names} /> : <p className="text-[0.9rem] text-muted">Choose a role.</p>}
      />
      <CreateRole tenant={tenant} open={creating} onOpenChange={setCreating} clientNames={names} />
    </>
  );
}

function CreateRole({ tenant, open, onOpenChange, clientNames }: { tenant: string; open: boolean; onOpenChange: (o: boolean) => void; clientNames: Record<string, string> }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [clientId, setClientId] = useState("");
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/roles", { params: { path: { slug: tenant } }, body: { name: name.trim(), description: description.trim() || null, client_id: clientId || null } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["roles", tenant] });
      setName("");
      setDescription("");
      onOpenChange(false);
      router.push(href("roles", tenant, { role: r.id }));
    },
  });
  return (
    <CreateDialog open={open} onOpenChange={onOpenChange} title="New role" submitLabel="Create role" pending={create.isPending} error={create.error?.message ?? null} onSubmit={() => name.trim() && create.mutate()}>
      <Field label="Name">{(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus required />}</Field>
      <Field label="Description">{(id) => <TextInput id={id} value={description} onChange={(e) => setDescription(e.target.value)} />}</Field>
      <Field label="Scope" hint="A client role only means something to that client.">
        {(id, by) => (
          <SelectInput id={id} aria-describedby={by} value={clientId} onChange={(e) => setClientId(e.target.value)}>
            <option value="">Realm (whole tenant)</option>
            {Object.entries(clientNames)
              .sort((a, b) => a[1].localeCompare(b[1]))
              .map(([cid, n]) => (
                <option key={cid} value={cid}>
                  {n}
                </option>
              ))}
          </SelectInput>
        )}
      </Field>
    </CreateDialog>
  );
}

function RoleDetailView({ tenant, id, clientNames }: { tenant: string; id: string; clientNames: Record<string, string> }) {
  const { client, can, me } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const query = useQuery({
    queryKey: ["role", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/roles/{role}", { params: { path: { slug: tenant, role: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<RoleDetail | null>(null);
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
  const editable = can("ridm:roles:write") && !(draft?.built_in ?? false);
  const save = useCallback(
    async (patch: { name?: string; description?: string | null }, { keepalive }: SaveOptions) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/roles/{role}", { params: { path: { slug: tenant, role: id } }, body: patch as never, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["role", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["role", tenant, id], (old: RoleDetail | undefined) => (old ? { ...old, ...data } : old));
      void qc.invalidateQueries({ queryKey: ["roles", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save);
  const update = (patch: Partial<Role>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
    if (editable) queue(patch);
  };
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/roles/{role}", { params: { path: { slug: tenant, role: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["roles", tenant] });
      router.push(href("roles", tenant));
    },
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["role", tenant, id] }).then(() => setResetCount((n) => n + 1));
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading role…" />;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">
          {draft.client_id && <span className="text-muted">{clientNames[draft.client_id] ?? "client"} / </span>}
          {draft.name} {draft.built_in && <Badge>built-in</Badge>}
        </h2>
        <SaveIndicator status={status} error={error} />
      </div>
      <Section id="role" title="Role" description={draft.built_in ? "Built-in roles keep their name, description and permissions." : undefined}>
        <Field label="Name">{(fid) => <TextInput id={fid} value={draft.name} disabled={!editable} onChange={(e) => update({ name: e.target.value })} />}</Field>
        <Field label="Description">{(fid) => <TextInput id={fid} value={draft.description ?? ""} disabled={!editable} onChange={(e) => update({ description: e.target.value || null })} />}</Field>
      </Section>
      <Composites tenant={tenant} id={id} composites={draft.composites} editable={can("ridm:roles:write") && !draft.built_in} clientNames={clientNames} onChanged={refresh} />
      <RolePermissions tenant={tenant} id={id} permissions={draft.permissions} editable={can("ridm:resource-servers:write") && !draft.built_in} onChanged={refresh} />
      <Holders tenant={tenant} id={id} />
      {can("ridm:roles:write") && !draft.built_in && me && <DeleteButton what="role" pending={del.isPending} error={del.error?.message ?? null} onConfirm={() => del.mutate()} description="Every assignment of this role is removed." />}
    </div>
  );
}

function Composites({ tenant, id, composites, editable, clientNames, onChanged }: { tenant: string; id: string; composites: Role[]; editable: boolean; clientNames: Record<string, string>; onChanged: () => void }) {
  const { client } = useConsole();
  const { roles: all } = useRolesAndGroups(tenant);
  const [pick, setPick] = useState("");
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await client.PUT("/admin/tenants/{slug}/roles/{role}/composites/{child_id}", { params: { path: { slug: tenant, role: id, child_id: what.add } } })
        : await client.DELETE("/admin/tenants/{slug}/roles/{role}/composites/{child_id}", { params: { path: { slug: tenant, role: id, child_id: what.remove! } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      setPick("");
      onChanged();
    },
  });
  const have = new Set(composites.map((r) => r.id));
  const label = (r: Role) => (r.client_id ? `${clientNames[r.client_id] ?? "client"} / ${r.name}` : r.name);
  return (
    <Card title="Composite roles">
      <p className="mb-2 text-[0.8125rem] text-muted">Holders of this role also hold these.</p>
      {composites.length === 0 && <p className="text-[0.875rem] text-muted">None.</p>}
      <ul className="divide-y divide-line">
        {composites.map((r) => (
          <li key={r.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
            <span className="font-medium text-ink">{label(r)}</span>
            {editable && (
              <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={change.isPending} onClick={() => change.mutate({ remove: r.id })}>
                Remove
              </Button>
            )}
          </li>
        ))}
      </ul>
      {editable && (
        <form
          className="mt-3 flex gap-2 border-t border-line pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (pick) change.mutate({ add: pick });
          }}
        >
          <SelectInput aria-label="Role to include" value={pick} onChange={(e) => setPick(e.target.value)}>
            <option value="">Choose a role…</option>
            {(all.data ?? [])
              .filter((r) => r.id !== id && !have.has(r.id))
              .map((r) => (
                <option key={r.id} value={r.id}>
                  {label(r)}
                </option>
              ))}
          </SelectInput>
          <Button type="submit" variant="primary" disabled={!pick || change.isPending}>
            Include
          </Button>
        </form>
      )}
      <ErrorLine error={change.error} />
    </Card>
  );
}

function RolePermissions({ tenant, id, permissions, editable, onChanged }: { tenant: string; id: string; permissions: RoleDetail["permissions"]; editable: boolean; onChanged: () => void }) {
  const { client } = useConsole();
  const servers = useResourceServers(tenant);
  const [pick, setPick] = useState("");
  const catalogue = useQuery({
    queryKey: ["permissions", tenant, servers.data?.map((r) => r.id) ?? []],
    staleTime: 60_000,
    enabled: editable && Boolean(servers.data),
    queryFn: async () => {
      const out: { id: string; label: string }[] = [];
      for (const rs of servers.data ?? []) {
        const { data } = await client.GET("/admin/tenants/{slug}/resource-servers/{rs}/permissions", { params: { path: { slug: tenant, rs: rs.id } } });
        for (const p of data ?? []) out.push({ id: p.id, label: `${rs.name}: ${p.name}` });
      }
      return out.sort((a, b) => a.label.localeCompare(b.label));
    },
  });
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await client.PUT("/admin/tenants/{slug}/roles/{role}/permissions/{permission_id}", { params: { path: { slug: tenant, role: id, permission_id: what.add } } })
        : await client.DELETE("/admin/tenants/{slug}/roles/{role}/permissions/{permission_id}", { params: { path: { slug: tenant, role: id, permission_id: what.remove! } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      setPick("");
      onChanged();
    },
  });
  const have = new Set(permissions.map((p) => p.id));
  const serverName = (rsId: string) => servers.data?.find((r) => r.id === rsId)?.name ?? "";
  return (
    <Card title="Permissions">
      <p className="mb-2 text-[0.8125rem] text-muted">Carried into access tokens for the matching audience. Admin-catalogue permissions can only be granted by someone who holds them.</p>
      {permissions.length === 0 && <p className="text-[0.875rem] text-muted">None.</p>}
      <ul className="divide-y divide-line">
        {permissions.map((p) => (
          <li key={p.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
            <span>
              <span className="font-mono text-[0.8125rem] font-medium text-ink">{p.name}</span>
              <span className="ms-2 text-muted">{serverName(p.resource_server_id)}</span>
            </span>
            {editable && (
              <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={change.isPending} onClick={() => change.mutate({ remove: p.id })}>
                Revoke
              </Button>
            )}
          </li>
        ))}
      </ul>
      {editable && (
        <form
          className="mt-3 flex gap-2 border-t border-line pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (pick) change.mutate({ add: pick });
          }}
        >
          <SelectInput aria-label="Permission to grant" value={pick} onChange={(e) => setPick(e.target.value)}>
            <option value="">Choose a permission…</option>
            {(catalogue.data ?? [])
              .filter((p) => !have.has(p.id))
              .map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
          </SelectInput>
          <Button type="submit" variant="primary" disabled={!pick || change.isPending}>
            Grant
          </Button>
        </form>
      )}
      <ErrorLine error={change.error} />
    </Card>
  );
}

function Holders({ tenant, id }: { tenant: string; id: string }) {
  const { client } = useConsole();
  const { groups } = useRolesAndGroups(tenant);
  const holders = useQuery({
    queryKey: ["role", tenant, id, "holders"],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/roles/{role}/holders", { params: { path: { slug: tenant, role: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      const users: Record<string, string> = {};
      await Promise.all(
        data
          .filter((a) => a.user_id)
          .slice(0, 50)
          .map(async (a) => {
            const r = await client.GET("/admin/tenants/{slug}/users/{user}", { params: { path: { slug: tenant, user: a.user_id! } } });
            if (r.data) users[a.user_id!] = r.data.username;
          }),
      );
      return { assignments: data, users };
    },
  });
  const groupName = (gid: string) => groups.data?.find((g) => g.id === gid)?.name ?? gid;
  return (
    <Card title="Held by">
      {holders.isPending ? (
        <Spinner label="Loading…" />
      ) : holders.isError ? (
        <ErrorLine error={holders.error} />
      ) : holders.data.assignments.length === 0 ? (
        <p className="text-[0.875rem] text-muted">Nobody holds this role directly.</p>
      ) : (
        <ul className="flex flex-wrap gap-1.5">
          {holders.data.assignments.map((a) =>
            a.user_id ? (
              <Link key={a.id} href={userHref(tenant, a.user_id, "roles")} className="inline-flex items-center rounded-full bg-ground px-2 py-0.5 text-[0.8125rem] text-ink hover:underline underline-offset-4">
                {holders.data.users[a.user_id] ?? a.user_id}
              </Link>
            ) : (
              <Link key={a.id} href={href("groups", tenant, { group: a.group_id! })} className="inline-flex items-center rounded-full bg-[color-mix(in_oklab,var(--accent)_14%,transparent)] px-2 py-0.5 text-[0.8125rem] text-link hover:underline underline-offset-4">
                group: {groupName(a.group_id!)}
              </Link>
            ),
          )}
        </ul>
      )}
    </Card>
  );
}
