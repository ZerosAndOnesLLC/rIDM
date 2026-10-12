"use client";

import { fmtDate } from "@/lib/console/format";
import { useInfiniteQuery } from "@tanstack/react-query";
import { Download, Mail, Plus, Upload, UsersRound } from "lucide-react";
import { useState } from "react";
import { DataTable, ListFooter, type Column } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { ChipSelect, ChipToggle, TextInput } from "@/components/console/form";
import { Badge, Button, PageHeader } from "@/components/console/ui";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { STATUS_LABELS, statusTone, userHref, type UserStatus } from "@/lib/console/users";

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
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = users;
  const writer = can("ridm:users:write");
  type Row = (typeof rows)[number];
  const columns: Column<Row>[] = [
    { key: "username", header: "Username", width: "minmax(10rem, 2fr)", cell: (u) => <span className="truncate font-medium text-ink">{u.username}</span> },
    {
      key: "email",
      header: "Email",
      width: "minmax(10rem, 2fr)",
      cell: (u) => (
        <span className="truncate text-muted">
          {u.email ?? "—"}
          {u.email && !u.email_verified && <span className="ms-1 text-caption">(unverified)</span>}
        </span>
      ),
    },
    { key: "status", header: "Status", width: "7rem", cell: (u) => <Badge tone={statusTone(u.status)}>{STATUS_LABELS[u.status]}</Badge> },
    { key: "last_login", header: "Last sign-in", width: "9rem", cell: (u) => <span className="text-muted">{u.last_login_at ? fmtDate(u.last_login_at) : "Never"}</span> },
  ];

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
        <TextInput aria-label="Search users" placeholder="Filter by username or email…" value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-xs flex-1 basis-[15rem]" />
        <ChipSelect label="Status" value={status} onChange={(v) => setStatus(v as UserStatus | "")}>
          <option value="">any</option>
          {(Object.keys(STATUS_LABELS) as UserStatus[])
            .filter((s) => s !== "deleted")
            .map((s) => (
              <option key={s} value={s}>
                {STATUS_LABELS[s]}
              </option>
            ))}
        </ChipSelect>
        <ChipToggle label="Include deleted" checked={deleted} onChange={setDeleted} />
      </div>
      {users.isError ? (
        <p role="alert" className="text-lead text-danger">
          {users.error.message}
        </p>
      ) : (
        <DataTable
          label="Users"
          columns={columns}
          rows={rows}
          rowKey={(u) => u.id}
          rowHref={(u) => userHref(tenant, u.id)}
          loading={users.isPending}
          virtualize
          onEndReached={() => {
            if (hasNextPage && !isFetchingNextPage) void fetchNextPage();
          }}
          empty={
            q || status ? (
              <EmptyState icon={UsersRound} title="No user matches" description="Try another name, email or status." />
            ) : (
              <EmptyState icon={UsersRound} title="No users yet" description="Create the first user, invite people by email, or import a file." action={writer ? <Button variant="primary" onClick={onCreate}>New user</Button> : undefined} />
            )
          }
          footer={<ListFooter mode="auto" count={rows.length} hasMore={Boolean(hasNextPage)} loading={isFetchingNextPage} />}
        />
      )}
    </>
  );
}
