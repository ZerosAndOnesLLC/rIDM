"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { AppWindow, Plus } from "lucide-react";
import { useState } from "react";
import { DataTable, ListFooter, type Column } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { TextInput } from "@/components/console/form";
import { Badge, Button, PageHeader } from "@/components/console/ui";
import { formatDate } from "@/i18n";
import { AUTH_METHODS, clientHref, samlHref, typeLabel } from "@/lib/console/clients";
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
  const columns: Column<Row>[] = [
    { key: "name", header: "Client", width: "minmax(10rem, 2fr)", cell: (c) => <span className="truncate font-medium text-ink">{c.name}</span> },
    { key: "client_id", header: "Client ID", width: "minmax(8rem, 1.5fr)", cell: (c) => <span className="truncate font-mono text-small text-muted">{c.client_id}</span> },
    { key: "type", header: "Type", width: "minmax(7rem, 1fr)", cell: (c) => <span className="truncate text-muted">{typeLabel(c.client_type)}</span> },
    { key: "auth", header: "Authentication", width: "minmax(8rem, 1fr)", cell: (c) => <span className="truncate text-muted">{AUTH_METHODS.find((m) => m.value === c.token_endpoint_auth_method)?.label ?? c.token_endpoint_auth_method}</span> },
    { key: "status", header: "Status", width: "6rem", cell: (c) => (c.status === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="danger">Disabled</Badge>) },
    { key: "created", header: "Created", width: "8rem", cell: (c) => <span className="text-muted">{formatDate("en", c.created_at, { dateStyle: "medium" })}</span> },
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
      <div className="mb-4 max-w-sm">
        <TextInput aria-label="Search clients" placeholder="Search by client ID or name…" value={search} onChange={(e) => setSearch(e.target.value)} />
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
          rowHref={(c) => (c.client_type === "saml" ? samlHref(tenant, c.id) : clientHref(tenant, c.id))}
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
