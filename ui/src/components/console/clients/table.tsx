"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { AppWindow, ChevronRight, Plus } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { DataTable, ListFooter, type Column } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { TextInput } from "@/components/console/form";
import { Avatar, Button, PageHeader, Status } from "@/components/console/ui";
import { AUTH_METHODS, clientHref, samlHref, typeLabel } from "@/lib/console/clients";
import { fmtWhen } from "@/lib/console/format";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";

export function ClientsTable({ tenant, onCreate }: { tenant: string; onCreate: () => void }) {
  const { client, can } = useConsole();
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim(), 250);
  const clients = useInfiniteQuery({
    queryKey: ["clients", tenant, q],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/clients", {
        params: { path: { slug: tenant }, query: { search: q || undefined, cursor: pageParam, limit: 50 } },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const rows = clients.data?.pages.flatMap((p) => p.items) ?? [];
  type Row = (typeof rows)[number];
  const href = (c: Row) => (c.client_type === "saml" ? samlHref(tenant, c.id) : clientHref(tenant, c.id));
  const columns: Column<Row>[] = [
    {
      key: "name",
      header: "Client",
      width: "minmax(14rem, 2fr)",
      cell: (c) => (
        <>
          <Avatar name={c.name} />
          <span className="min-w-0">
            <span className="block truncate font-semibold leading-tight text-ink">{c.name}</span>
            <span className="block truncate font-mono text-caption leading-snug text-muted">{c.client_id}</span>
          </span>
        </>
      ),
    },
    { key: "type", header: "Type", width: "minmax(7rem, 1fr)", cell: (c) => <span className="truncate text-muted">{typeLabel(c.client_type)}</span> },
    { key: "auth", header: "Authentication", width: "minmax(8rem, 1fr)", cell: (c) => <span className="truncate text-muted">{AUTH_METHODS.find((m) => m.value === c.token_endpoint_auth_method)?.label ?? c.token_endpoint_auth_method}</span> },
    { key: "status", header: "Status", width: "6.5rem", cell: (c) => (c.status === "active" ? <Status tone="ok">Active</Status> : <Status tone="danger">Disabled</Status>) },
    { key: "created", header: "Created", width: "8rem", cell: (c) => <span className="font-mono text-caption text-muted">{fmtWhen(c.created_at)}</span> },
    {
      key: "open",
      header: "Open",
      hideHeader: true,
      width: "2.25rem",
      align: "end",
      cell: (c) => (
        <Link href={href(c)} aria-label={`Open ${c.name}`} className="row-action flex size-7 items-center justify-center rounded-[var(--radius)] text-muted no-underline hover:bg-ground hover:text-ink">
          <ChevronRight className="rtl-flip size-4" aria-hidden />
        </Link>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Clients"
        sub="Applications and services that obtain tokens from this tenant."
        actions={
          can("ridm:clients:write") ? (
            <Button variant="primary" onClick={onCreate}>
              <Plus className="size-4" aria-hidden />
              New client
            </Button>
          ) : undefined
        }
      />
      <div className="mb-3 max-w-xs">
        <TextInput aria-label="Search clients" placeholder="Filter by client ID or name…" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      {clients.isError ? (
        <p role="alert" className="text-lead text-danger">
          {clients.error.message}
        </p>
      ) : (
        <DataTable
          label="Clients"
          columns={columns}
          rows={rows}
          rowKey={(c) => c.id}
          rowHref={href}
          loading={clients.isPending}
          minWidth="48rem"
          empty={
            q ? (
              <EmptyState icon={AppWindow} title="No client matches" description="Try part of the client ID or name." />
            ) : (
              <EmptyState icon={AppWindow} title="No clients yet" description="A client is an application or service that obtains tokens from this tenant." action={can("ridm:clients:write") ? <Button variant="primary" onClick={onCreate}>New client</Button> : undefined} />
            )
          }
          footer={<ListFooter mode="more" count={rows.length} hasMore={clients.hasNextPage} loading={clients.isFetchingNextPage} onMore={() => void clients.fetchNextPage()} />}
        />
      )}
    </>
  );
}
