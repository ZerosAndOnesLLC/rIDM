"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import { ChevronRight, Download, KeyRound, Mail, MessageSquare, Plus, Smartphone, Upload, UsersRound } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { DataTable, ListFooter, type Column } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { ChipSelect, ChipToggle, TextInput } from "@/components/console/form";
import { Avatar, Button, PageHeader, Status } from "@/components/console/ui";
import { fmtWhen, isFresh } from "@/lib/console/format";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { STATUS_LABELS, displayName, statusTone, userHref, type UserStatus } from "@/lib/console/users";

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
    {
      key: "user",
      header: "User",
      width: "minmax(12rem, 2fr)",
      cell: (u) => {
        const name = displayName(u);
        return (
          <>
            <Avatar name={u.username} />
            <span className="min-w-0">
              <span className="block truncate font-semibold leading-tight text-ink">{name ?? u.username}</span>
              {name && <span className="block truncate text-caption leading-snug text-muted">{u.username}</span>}
            </span>
          </>
        );
      },
    },
    {
      key: "email",
      header: "Email",
      width: "minmax(10rem, 2fr)",
      cell: (u) => (
        <span className="truncate text-muted">
          {u.email ?? "—"}
          {u.email && !u.email_verified && <span className="ms-1.5 text-caption text-warn">unverified</span>}
        </span>
      ),
    },
    { key: "status", header: "Status", width: "6.5rem", cell: (u) => <Status tone={statusTone(u.status)}>{STATUS_LABELS[u.status]}</Status> },
    {
      key: "last_login",
      header: "Last sign-in",
      width: "8.5rem",
      cell: (u) => (
        <span className={`inline-flex items-center gap-1.5 font-mono text-caption ${isFresh(u.last_login_at) ? "text-ink-2" : "text-muted"}`}>
          <i aria-hidden className={`size-1.5 rounded-full ${isFresh(u.last_login_at) ? "bg-ok" : "bg-line-strong"}`} />
          {u.last_login_at ? fmtWhen(u.last_login_at) : "Never"}
        </span>
      ),
    },
    {
      key: "second_step",
      header: "Second step",
      width: "6.5rem",
      cell: (u) => <SecondStep step={u.second_step ?? null} />,
    },
    {
      key: "open",
      header: "Open",
      hideHeader: true,
      width: "2.25rem",
      align: "end",
      cell: (u) => (
        <Link href={userHref(tenant, u.id)} aria-label={`Open ${u.username}`} className="row-action flex size-7 items-center justify-center rounded-[var(--radius)] text-muted no-underline hover:bg-ground hover:text-ink">
          <ChevronRight className="rtl-flip size-4" aria-hidden />
        </Link>
      ),
    },
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
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
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
          minWidth="46rem"
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

/** The strongest second step enrolled, as a glyph with its name for assistive tech. */
export function SecondStep({ step }: { step: string | null }) {
  if (!step) return <span className="text-muted">—</span>;
  const [Icon, label] = step === "passkey" ? [KeyRound, "Passkey"] : step === "totp" ? [Smartphone, "Authenticator app"] : [MessageSquare, "Emailed or texted codes"];
  return (
    <span className="inline-flex items-center gap-1.5 text-accent-text" title={label}>
      <Icon className="size-[0.9375rem]" aria-hidden />
      <span className="sr-only">{label}</span>
    </span>
  );
}
