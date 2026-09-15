"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { Download, Mail, Plus, Upload } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { SelectInput, TextInput } from "@/components/console/form";
import { Badge, Button, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { formatDate } from "@/i18n";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { useRowWindow } from "@/lib/console/virtual";
import { STATUS_LABELS, statusTone, userHref, type UserStatus } from "@/lib/console/users";

const ROW = 48;

export function UsersTable({ tenant, onCreate, onInvite, onImport, onExport }: { tenant: string; onCreate: () => void; onInvite: () => void; onImport: () => void; onExport: () => void }) {
  const { client, can } = useConsole();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<UserStatus | "">("");
  const [deleted, setDeleted] = useState(false);
  const q = useDebounced(search.trim(), 250);
  const users = useInfiniteQuery({
    queryKey: ["users", tenant, q, status, deleted],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/users", {
        params: { path: { slug: tenant }, query: { search: q || undefined, status: status || undefined, include_deleted: deleted || undefined, cursor: pageParam, limit: 100 } },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const rows = users.data?.pages.flatMap((p) => p.items) ?? [];
  const parentRef = useRef<HTMLDivElement>(null);
  const { items, totalSize } = useRowWindow(rows.length, ROW, parentRef);
  const last = items[items.length - 1];
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = users;
  useEffect(() => {
    if (last && last.index >= rows.length - 20 && hasNextPage && !isFetchingNextPage) void fetchNextPage();
  }, [last, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage]);
  const writer = can("ridm:users:write");

  return (
    <>
      <PageHeader
        title="Users"
        sub="Everyone who can sign in to this tenant."
        actions={
          <>
            <Button onClick={onExport}>
              <Download className="size-4" aria-hidden />
              Export
            </Button>
            {writer && (
              <Button onClick={onImport}>
                <Upload className="size-4" aria-hidden />
                Import
              </Button>
            )}
            {can("ridm:invitations:write") && (
              <Button onClick={onInvite}>
                <Mail className="size-4" aria-hidden />
                Invite
              </Button>
            )}
            {writer && (
              <Button variant="primary" onClick={onCreate}>
                <Plus className="size-4" aria-hidden />
                New user
              </Button>
            )}
          </>
        }
      />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <TextInput aria-label="Search users" placeholder="Search by username or email…" value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-sm" />
        <SelectInput aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value as UserStatus | "")} className="max-w-[12rem]">
          <option value="">Any status</option>
          {(Object.keys(STATUS_LABELS) as UserStatus[])
            .filter((s) => s !== "deleted")
            .map((s) => (
              <option key={s} value={s}>
                {STATUS_LABELS[s]}
              </option>
            ))}
        </SelectInput>
        <label className="flex items-center gap-2 text-[0.875rem] text-ink">
          <input type="checkbox" className="size-4 accent-[var(--accent)]" checked={deleted} onChange={(e) => setDeleted(e.target.checked)} />
          Include deleted
        </label>
        <span className="ms-auto text-[0.8125rem] text-muted" aria-live="polite">
          {rows.length}
          {users.hasNextPage ? "+" : ""} shown
        </span>
      </div>
      {users.isError ? (
        <p role="alert" className="text-[0.9rem] text-danger">
          {users.error.message}
        </p>
      ) : users.isPending ? (
        <Spinner label="Loading users…" />
      ) : (
        <div className="overflow-x-auto rounded-[calc(var(--radius)+2px)] border border-line bg-paper">
          <div role="table" aria-label="Users" aria-rowcount={rows.length} className="min-w-[38rem] text-[0.875rem]">
            <div role="row" className="grid grid-cols-[minmax(10rem,2fr)_minmax(10rem,2fr)_7rem_9rem] gap-3 border-b border-line px-4 py-2.5 text-[0.75rem] uppercase tracking-wide text-muted">
              <span role="columnheader">Username</span>
              <span role="columnheader">Email</span>
              <span role="columnheader">Status</span>
              <span role="columnheader">Last sign-in</span>
            </div>
            {rows.length === 0 ? (
              <p className="px-4 py-8 text-center text-muted">{q || status ? "No user matches." : "No users yet."}</p>
            ) : (
              <div ref={parentRef} className="max-h-[calc(100vh-18rem)] overflow-y-auto">
                <div role="rowgroup" style={{ height: totalSize, position: "relative" }}>
                  {items.map((v) => {
                    const u = rows[v.index]!;
                    return (
                      <div
                        key={u.id}
                        role="row"
                        aria-rowindex={v.index + 1}
                        style={{ position: "absolute", top: 0, left: 0, width: "100%", height: v.size, transform: `translateY(${v.start}px)` }}
                        className="grid grid-cols-[minmax(10rem,2fr)_minmax(10rem,2fr)_7rem_9rem] items-center gap-3 border-b border-line px-4 hover:bg-ground/60"
                      >
                        <span role="cell" className="min-w-0 truncate font-medium text-ink">
                          <Link href={userHref(tenant, u.id)} className="hover:underline underline-offset-4">
                            {u.username}
                          </Link>
                        </span>
                        <span role="cell" className="min-w-0 truncate text-muted">
                          {u.email ?? "—"}
                          {u.email && !u.email_verified && <span className="ms-1 text-[0.75rem]">(unverified)</span>}
                        </span>
                        <span role="cell">
                          <Badge tone={statusTone(u.status)}>{STATUS_LABELS[u.status]}</Badge>
                        </span>
                        <span role="cell" className="text-muted">
                          {u.last_login_at ? formatDate("en", u.last_login_at, { dateStyle: "medium" }) : "Never"}
                        </span>
                      </div>
                    );
                  })}
                </div>
                {users.isFetchingNextPage && <p className="py-2 text-center text-[0.8125rem] text-muted">Loading more…</p>}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
