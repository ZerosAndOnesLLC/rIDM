"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, Plus, UserRoundPlus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useMemo, useState } from "react";
import { Picker, type PickerItem } from "@/components/console/picker";
import { Field, SaveIndicator, Section, SelectInput, TextInput } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { groupPaths, href, type Group, type GroupDetail } from "@/lib/console/access";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { roleName, userHref } from "@/lib/console/users";
import { JsonInput } from "../users/attributes";
import { useRolesAndGroups } from "../users/invite";
import { CreateDialog, DeleteButton, ErrorLine, Split } from "./common";
import { MemberList } from "./member-list";

export function GroupsPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { can } = useConsole();
  const { groups } = useRolesAndGroups(tenant);
  const [creating, setCreating] = useState<{ parent: string | null } | null>(null);
  const all = useMemo(() => groups.data ?? [], [groups.data]);
  const tree = useMemo(() => childrenIndex(all), [all]);

  return (
    <>
      <PageHeader
        title="Groups"
        sub="Nested groups; members inherit the roles of every ancestor."
        actions={
          can("ridm:groups:write") ? (
            <Button variant="primary" onClick={() => setCreating({ parent: null })}>
              <Plus className="size-4" aria-hidden />
              New group
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Tree">
            {groups.isPending ? <Spinner label="Loading…" /> : groups.isError ? <ErrorLine error={groups.error} /> : all.length === 0 ? <p className="text-[0.875rem] text-muted">No groups yet.</p> : <GroupTree tree={tree} parent={null} depth={0} tenant={tenant} selected={selected} />}
          </Card>
        }
        detail={selected ? <GroupDetailView key={selected} tenant={tenant} id={selected} all={all} onCreateChild={() => setCreating({ parent: selected })} /> : <p className="text-[0.9rem] text-muted">Choose a group.</p>}
      />
      <CreateGroup tenant={tenant} all={all} open={creating !== null} parent={creating?.parent ?? null} onOpenChange={(o) => !o && setCreating(null)} />
    </>
  );
}

/** Each group's children, sorted by name, built once per group list (the tree renders from it without scanning the list per node). */
function childrenIndex(all: Group[]): Map<string | null, Group[]> {
  const index = new Map<string | null, Group[]>();
  for (const g of all) {
    const parent = g.parent_id ?? null;
    const list = index.get(parent);
    if (list) list.push(g);
    else index.set(parent, [g]);
  }
  for (const list of index.values()) list.sort((a, b) => a.name.localeCompare(b.name));
  return index;
}

/** Every group below `id` in the tree. */
function descendantsOf(tree: Map<string | null, Group[]>, id: string): Set<string> {
  const out = new Set<string>();
  const stack = [id];
  while (stack.length) {
    for (const g of tree.get(stack.pop() as string) ?? []) {
      if (!out.has(g.id)) {
        out.add(g.id);
        stack.push(g.id);
      }
    }
  }
  return out;
}

function GroupTree({ tree, parent, depth, tenant, selected }: { tree: Map<string | null, Group[]>; parent: string | null; depth: number; tenant: string; selected: string | null }) {
  return (
    <ul role={depth === 0 ? "tree" : "group"} className={depth ? "ms-4 border-s border-line" : ""}>
      {(tree.get(parent) ?? []).map((g) => {
        const kids = tree.get(g.id)?.length ?? 0;
        return (
          <li key={g.id} role="treeitem" aria-selected={g.id === selected} aria-expanded={kids ? true : undefined}>
            <Link
              href={href("groups", tenant, { group: g.id })}
              aria-current={g.id === selected ? "page" : undefined}
              className={`flex items-center gap-1.5 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${g.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
            >
              <ChevronRight className={`size-3.5 shrink-0 text-muted ${kids ? "" : "invisible"}`} aria-hidden />
              <span className="truncate">{g.name}</span>
            </Link>
            {kids > 0 && <GroupTree tree={tree} parent={g.id} depth={depth + 1} tenant={tenant} selected={selected} />}
          </li>
        );
      })}
    </ul>
  );
}

function CreateGroup({ tenant, all, open, parent, onOpenChange }: { tenant: string; all: Group[]; open: boolean; parent: string | null; onOpenChange: (o: boolean) => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [name, setName] = useState("");
  const [parentId, setParentId] = useState<string>(parent ?? "");
  const [seenParent, setSeenParent] = useState(parent);
  if (seenParent !== parent) {
    setSeenParent(parent);
    setParentId(parent ?? "");
  }
  const paths = groupPaths(all);
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/groups", { params: { path: { slug: tenant } }, body: { name: name.trim(), parent_id: parentId || null, description: null, attributes: null } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (g) => {
      void qc.invalidateQueries({ queryKey: ["groups", tenant] });
      setName("");
      onOpenChange(false);
      router.push(href("groups", tenant, { group: g.id }));
    },
  });
  return (
    <CreateDialog open={open} onOpenChange={onOpenChange} title="New group" submitLabel="Create group" pending={create.isPending} error={create.error?.message ?? null} onSubmit={() => name.trim() && create.mutate()}>
      <Field label="Name">{(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} autoFocus required />}</Field>
      <Field label="Parent">
        {(id) => (
          <SelectInput id={id} value={parentId} onChange={(e) => setParentId(e.target.value)}>
            <option value="">None (top level)</option>
            {[...paths.entries()].sort((a, b) => a[1].localeCompare(b[1])).map(([gid, p]) => (
              <option key={gid} value={gid}>
                {p}
              </option>
            ))}
          </SelectInput>
        )}
      </Field>
    </CreateDialog>
  );
}

function GroupDetailView({ tenant, id, all, onCreateChild }: { tenant: string; id: string; all: Group[]; onCreateChild: () => void }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const editable = can("ridm:groups:write");
  const query = useQuery({
    queryKey: ["group", tenant, id],
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/groups/{group}", { params: { path: { slug: tenant, group: id } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
  const [draft, setDraft] = useState<GroupDetail | null>(null);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);
  const save = useCallback(
    async (patch: { name?: string; description?: string | null; parent_id?: string | null; attributes?: unknown }, { keepalive }: SaveOptions) => {
      const { data, error } = await client.PATCH("/admin/tenants/{slug}/groups/{group}", { params: { path: { slug: tenant, group: id } }, body: patch as never, keepalive });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["group", tenant, id] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["group", tenant, id], (old: GroupDetail | undefined) => (old ? { ...old, ...data } : old));
      void qc.invalidateQueries({ queryKey: ["groups", tenant] });
    },
    [client, qc, tenant, id],
  );
  const { queue, status, error } = useAutoSave(save, { baseline: query.data });
  const paths = useMemo(() => groupPaths(all), [all]);
  // A group cannot move under itself or a descendant.
  const descendants = useMemo(() => descendantsOf(childrenIndex(all), id), [all, id]);
  const update = (patch: Partial<GroupDetail>) => {
    setDraft((d) => (d ? { ...d, ...patch } : d));
    if (editable) queue(patch);
  };
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await client.DELETE("/admin/tenants/{slug}/groups/{group}", { params: { path: { slug: tenant, group: id } } });
      if (error) throw new Error(error.detail ?? error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["groups", tenant] });
      router.push(href("groups", tenant));
    },
  });
  if (query.isError) return <ErrorLine error={query.error} />;
  if (!draft) return <Spinner label="Loading group…" />;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-[1.125rem] font-semibold text-ink">{paths.get(id) ?? draft.name}</h2>
        <span className="flex items-center gap-2">
          <SaveIndicator status={status} error={error} />
          {editable && (
            <Button onClick={onCreateChild}>
              <Plus className="size-4" aria-hidden />
              Subgroup
            </Button>
          )}
        </span>
      </div>
      <Section id="group" title="Group" description={`${draft.member_count} direct member${draft.member_count === 1 ? "" : "s"}.`}>
        <Field label="Name">{(fid) => <TextInput id={fid} value={draft.name} disabled={!editable} onChange={(e) => update({ name: e.target.value })} />}</Field>
        <Field label="Parent">
          {(fid) => (
            <SelectInput id={fid} value={draft.parent_id ?? ""} disabled={!editable} onChange={(e) => update({ parent_id: e.target.value || null })}>
              <option value="">None (top level)</option>
              {[...paths.entries()]
                .filter(([gid]) => gid !== id && !descendants.has(gid))
                .sort((a, b) => a[1].localeCompare(b[1]))
                .map(([gid, p]) => (
                  <option key={gid} value={gid}>
                    {p}
                  </option>
                ))}
            </SelectInput>
          )}
        </Field>
        <Field label="Description" wide>{(fid) => <TextInput id={fid} value={draft.description ?? ""} disabled={!editable} onChange={(e) => update({ description: e.target.value || null })} />}</Field>
        <Field label="Attributes" hint="Free-form JSON object." wide>
          {(fid, by) => <JsonInput id={fid} describedBy={by} value={draft.attributes ?? null} disabled={!editable} onChange={(v) => update({ attributes: v ?? {} })} />}
        </Field>
      </Section>
      <GroupRoles tenant={tenant} id={id} roles={draft.roles} editable={editable} onChanged={() => setResetCount((n) => n + 1)} />
      <GroupMembers tenant={tenant} id={id} editable={editable} />
      {editable && <DeleteButton what="group" pending={del.isPending} error={del.error?.message ?? null} onConfirm={() => del.mutate()} description="Members lose the roles this group carried; subgroups move up a level." />}
    </div>
  );
}

function GroupRoles({ tenant, id, roles, editable, onChanged }: { tenant: string; id: string; roles: GroupDetail["roles"]; editable: boolean; onChanged: () => void }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const { roles: all } = useRolesAndGroups(tenant);
  const [pick, setPick] = useState("");
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await client.PUT("/admin/tenants/{slug}/groups/{group}/roles/{role_id}", { params: { path: { slug: tenant, group: id, role_id: what.add } } })
        : await client.DELETE("/admin/tenants/{slug}/groups/{group}/roles/{role_id}", { params: { path: { slug: tenant, group: id, role_id: what.remove! } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: async () => {
      setPick("");
      await qc.invalidateQueries({ queryKey: ["group", tenant, id] });
      onChanged();
    },
  });
  const have = new Set(roles.map((r) => r.id));
  return (
    <Card title="Roles of this group">
      {roles.length === 0 && <p className="text-[0.875rem] text-muted">No roles; members inherit only from ancestors.</p>}
      <ul className="divide-y divide-line">
        {roles.map((r) => (
          <li key={r.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
            <span className="font-medium text-ink">
              {roleName(r)} {r.built_in && <Badge>built-in</Badge>}
            </span>
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
          <SelectInput aria-label="Role to add" value={pick} onChange={(e) => setPick(e.target.value)}>
            <option value="">Choose a role…</option>
            {(all.data ?? [])
              .filter((r) => !have.has(r.id))
              .map((r) => (
                <option key={r.id} value={r.id}>
                  {roleName(r)}
                </option>
              ))}
          </SelectInput>
          <Button type="submit" variant="primary" disabled={!pick || change.isPending}>
            Add
          </Button>
        </form>
      )}
      <ErrorLine error={change.error} />
    </Card>
  );
}

function GroupMembers({ tenant, id, editable }: { tenant: string; id: string; editable: boolean }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [query, setQuery] = useState("");
  const q = useDebounced(query.trim(), 200);
  const candidates = useQuery({
    queryKey: ["users", tenant, "pick", q],
    enabled: adding && q.length >= 1,
    queryFn: async () => {
      const { data } = await client.GET("/admin/tenants/{slug}/users", { params: { path: { slug: tenant }, query: { search: q, limit: 10 } } });
      return data?.items ?? [];
    },
  });
  const change = useMutation({
    mutationFn: async (what: { add?: string; remove?: string }) => {
      const r = what.add
        ? await client.PUT("/admin/tenants/{slug}/groups/{group}/members/{user_id}", { params: { path: { slug: tenant, group: id, user_id: what.add } } })
        : await client.DELETE("/admin/tenants/{slug}/groups/{group}/members/{user_id}", { params: { path: { slug: tenant, group: id, user_id: what.remove! } } });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["group", tenant, id] });
    },
  });
  // Adding someone who is already a member changes nothing.
  const items: PickerItem[] = (candidates.data ?? [])
    .map((u) => ({ id: u.id, group: "Users", label: u.username, hint: u.email && u.email !== u.username ? u.email : undefined, onSelect: () => change.mutate({ add: u.id }) }));
  return (
    <Card
      title="Members"
      actions={
        editable ? (
          <Button className="min-h-8 px-2.5 text-[0.8125rem]" onClick={() => setAdding(true)}>
            <UserRoundPlus className="size-3.5" aria-hidden />
            Add member
          </Button>
        ) : undefined
      }
    >
      <MemberList
        tenant={tenant}
        of={{ kind: "group", id }}
        empty={<p className="text-[0.875rem] text-muted">No direct members.</p>}
        row={(u) => (
          <li key={u.id} className="flex items-center justify-between gap-3 py-2 text-[0.875rem]">
            <Link href={userHref(tenant, u.id, "groups")} className="font-medium text-ink hover:underline underline-offset-4">
              {u.username}
            </Link>
            {editable && (
              <Button variant="danger" className="min-h-8 px-2.5 text-[0.8125rem]" disabled={change.isPending} onClick={() => change.mutate({ remove: u.id })}>
                Remove
              </Button>
            )}
          </li>
        )}
      />
      <ErrorLine error={change.error} />
      <Picker open={adding} onOpenChange={setAdding} title="Add member" placeholder="Search users by username or email…" query={query} onQueryChange={setQuery} items={items} loading={candidates.isFetching} empty={q ? "No user matches." : "Type to search."} />
    </Card>
  );
}
