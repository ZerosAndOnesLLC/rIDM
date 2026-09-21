"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { TextInput } from "@/components/console/form";
import { Badge, Button, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
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
        <p role="alert" className="text-[0.9rem] text-danger">
          {clients.error.message}
        </p>
      ) : clients.isPending ? (
        <Spinner label="Loading clients…" />
      ) : (
        <div className="overflow-x-auto rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
          <table className="w-full text-[0.875rem]">
            <thead className="text-[0.75rem] uppercase tracking-wide text-muted">
              <tr className="border-b border-line">
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Client</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Client ID</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Type</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Authentication</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Status</th>
                <th scope="col" className="px-4 py-2.5 text-start font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted">
                    {q ? "No client matches." : "No clients yet."}
                  </td>
                </tr>
              )}
              {rows.map((c) => (
                <tr key={c.id} className="border-b border-line last:border-b-0 hover:bg-ground/60">
                  <td className="px-4 py-2.5 font-medium text-ink">
                    <Link href={c.client_type === "saml" ? samlHref(tenant, c.id) : clientHref(tenant, c.id)} className="hover:underline underline-offset-4">
                      {c.name}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[0.8125rem] text-muted">{c.client_id}</td>
                  <td className="px-4 py-2.5 text-muted">{typeLabel(c.client_type)}</td>
                  <td className="px-4 py-2.5 text-muted">{AUTH_METHODS.find((m) => m.value === c.token_endpoint_auth_method)?.label ?? c.token_endpoint_auth_method}</td>
                  <td className="px-4 py-2.5">{c.status === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="danger">Disabled</Badge>}</td>
                  <td className="px-4 py-2.5 text-muted">{formatDate("en", c.created_at, { dateStyle: "medium" })}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {clients.hasNextPage && (
            <div className="border-t border-line p-3 text-center">
              <Button onClick={() => void clients.fetchNextPage()} disabled={clients.isFetchingNextPage}>
                {clients.isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </div>
      )}
    </>
  );
}
