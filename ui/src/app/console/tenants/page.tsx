"use client";

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Plus, Settings2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { Field, SelectInput, TextInput } from "@/components/console/form";
import { DataTable, ListFooter, type Column } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { Badge, Button, Modal, PageHeader } from "@/components/console/ui";
import { formatDate } from "@/i18n";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { isValidSlug } from "@/lib/console/settings";
import { useConsoleTenant } from "@/lib/console/tenant";

/** Every tenant a global administrator reaches (or the caller's own), plus creation. */
export default function TenantsPage() {
  const { client, can, me } = useConsole();
  const current = useConsoleTenant();
  const [filter, setFilter] = useState("");
  const [creating, setCreating] = useState(false);
  const search = useDebounced(filter.trim(), 250);
  const tenants = useInfiniteQuery({
    queryKey: ["tenants", "list", search],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error } = await client.GET("/admin/tenants", { params: { query: { search: search || undefined, cursor: pageParam, limit: 100 } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const regions = useRegions(me?.scope === "global");
  const regional = (regions.data?.length ?? 0) > 1;
  const rows = tenants.data?.pages.flatMap((p) => p.items) ?? [];
  const canCreate = me?.scope === "global" && can("ridm:tenants:create");
  type Row = (typeof rows)[number];
  const columns: Column<Row>[] = [
    {
      key: "name",
      header: "Tenant",
      width: "minmax(10rem, 2fr)",
      cell: (t) => (
        <span className="min-w-0 truncate font-medium text-ink">
          {t.display_name}
          {t.slug === current && <span className="ms-2 text-caption font-normal text-muted">current</span>}
        </span>
      ),
    },
    { key: "slug", header: "Slug", width: "minmax(7rem, 1fr)", cell: (t) => <span className="truncate font-mono text-small text-muted">{t.slug}</span> },
    ...(regional ? [{ key: "region", header: "Region", width: "7rem", cell: (t: Row) => <span className="font-mono text-small text-muted">{t.data_region ?? "home"}</span> }] : []),
    { key: "status", header: "Status", width: "6.5rem", cell: (t) => (t.relocating ? <Badge tone="accent">Moving</Badge> : t.status === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="danger">Disabled</Badge>) },
    { key: "created", header: "Created", width: "8rem", cell: (t) => <span className="text-muted">{formatDate("en", t.created_at, { dateStyle: "medium" })}</span> },
    {
      key: "actions",
      header: "Actions",
      hideHeader: true,
      width: "6.5rem",
      align: "end",
      cell: (t) => (
        <Link href={`/console/settings/?tenant=${encodeURIComponent(t.slug)}`} className="inline-flex items-center gap-1.5 rounded-[var(--radius)] px-2.5 py-1.5 text-small text-link no-underline hover:bg-ground hover:underline">
          <Settings2 className="size-4" aria-hidden />
          Settings
        </Link>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Tenants"
        sub={me?.scope === "global" ? "Every tenant on this server." : "Your tenant."}
        actions={
          canCreate ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New tenant
            </Button>
          ) : undefined
        }
      />
      <div className="mb-4 max-w-sm">
        <TextInput aria-label="Filter tenants" placeholder="Slug or name starts with…" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      {tenants.isError ? (
        <p role="alert" className="text-lead text-danger">
          {tenants.error.message}
        </p>
      ) : (
        <DataTable
          label="Tenants"
          columns={columns}
          rows={rows}
          rowKey={(t) => t.id}
          loading={tenants.isPending}
          empty={<EmptyState icon={Building2} title="No tenant matches" description="Try a different slug or name." />}
          footer={<ListFooter mode="more" count={rows.length} hasMore={tenants.hasNextPage} loading={tenants.isFetchingNextPage} onMore={() => void tenants.fetchNextPage()} />}
        />
      )}
      {canCreate && <CreateTenant open={creating} onOpenChange={setCreating} regions={regional ? (regions.data ?? []) : []} />}
    </>
  );
}

type Region = { name: string; home: boolean; dedicated_cache: boolean; tenants: number };

/** The databases a tenant can be placed in (data residency); only global administrators may ask. */
function useRegions(enabled: boolean) {
  const { client } = useConsole();
  return useQuery({
    queryKey: ["regions"],
    enabled,
    queryFn: async (): Promise<Region[]> => {
      const { data, error } = await client.GET("/admin/regions");
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });
}

function CreateTenant({ open, onOpenChange, regions }: { open: boolean; onOpenChange: (o: boolean) => void; regions: Region[] }) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [region, setRegion] = useState("home");
  const [touched, setTouched] = useState(false);
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants", {
        body: { slug: slug.trim(), display_name: name.trim(), data_region: region === "home" ? null : region },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (t) => {
      void qc.invalidateQueries({ queryKey: ["tenants"] });
      onOpenChange(false);
      router.push(`/console/settings/?tenant=${encodeURIComponent(t.slug)}`);
    },
  });
  const slugError = touched && !isValidSlug(slug.trim()) ? "1–63 lowercase letters, digits or hyphens, not starting or ending with a hyphen." : null;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!isValidSlug(slug.trim()) || !name.trim()) return;
    create.mutate();
  };
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="New tenant" description="A tenant has its own users, clients, keys and issuer URL.">
      <form onSubmit={submit} className="flex flex-col gap-4 px-5 pb-5 pt-3" noValidate>
        <Field label="Display name">
          {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" autoFocus required />}
        </Field>
        <Field label="Slug" hint="Part of the issuer URL: /t/<slug>. Cannot change later." error={slugError}>
          {(id, by) => (
            <TextInput
              id={id}
              aria-describedby={by}
              aria-invalid={slugError ? true : undefined}
              value={slug}
              onChange={(e) => setSlug(e.target.value.toLowerCase())}
              onBlur={() => setTouched(true)}
              placeholder="acme"
              autoCapitalize="none"
              spellCheck={false}
              required
            />
          )}
        </Field>
        {regions.length > 1 && (
          <Field label="Data region" hint="Where the tenant's users, sessions and audit log are stored. Moving a tenant later takes ridm-api move-tenant.">
            {(id, by) => (
              <SelectInput id={id} aria-describedby={by} value={region} onChange={(e) => setRegion(e.target.value)}>
                {regions.map((r) => (
                  <option key={r.name} value={r.name}>
                    {r.home ? "home (the main database)" : r.name}
                  </option>
                ))}
              </SelectInput>
            )}
          </Field>
        )}
        {create.isError && (
          <p role="alert" className="text-body text-danger">
            {create.error.message}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create tenant"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
