"use client";

import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, Download, KeyRound, Mail, MessageSquare, Plus, Smartphone, Upload, UsersRound } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { BulkBar, bulkButtonClass } from "@/components/base/bulk-bar";
import { ConfirmDialog } from "@/components/base/confirm-dialog";
import { DataTable, ListFooter, type Column, type SortState } from "@/components/base/data-table";
import { EmptyState } from "@/components/base/empty-state";
import { useToast } from "@/components/base/toast";
import { ChipSelect, ChipToggle, TextInput } from "@/components/console/form";
import { Avatar, Button, PageHeader, Status } from "@/components/console/ui";
import { bulkToast, runBulk } from "@/lib/console/bulk";
import { fmtWhen, isFresh } from "@/lib/console/format";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { STATUS_LABELS, displayName, statusTone, userHref, type UserStatus, type UserUpdate } from "@/lib/console/users";
import { useQueryParams } from "@/lib/params";

const SORTS = ["created", "username", "email", "status", "last_login"] as const;
type Sort = (typeof SORTS)[number];
const STATUSES = Object.keys(STATUS_LABELS) as UserStatus[];

/**
 * The users list: filters and sort in the URL, sorted on the server with
 * keyset cursors, windowed rows, checkbox selection with a bulk bar for
 * enable, disable and delete.
 */
export function UsersTable({ tenant, onCreate, onInvite, onImport, onExport }: { tenant: string; onCreate: () => void; onInvite: () => void; onImport: () => void; onExport: () => void }) {
  const { client, can } = useConsole();
  const qc = useQueryClient();
  const { toast } = useToast();
  const params = useQueryParams();
  const [search, setSearch] = useState(params.get("q"));
  const q = useDebounced(search.trim(), 250);
  useEffect(() => params.set({ q }), [q, params]);
  const statusParam = params.get("status");
  const status: UserStatus | "" = (STATUSES as string[]).includes(statusParam) ? (statusParam as UserStatus) : "";
  const deleted = params.get("deleted") === "1";
  const sortParam = params.get("sort");
  const sort: SortState = { key: (SORTS as readonly string[]).includes(sortParam) ? sortParam : "created", dir: params.get("dir") === "desc" ? "desc" : "asc" };
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [confirm, setConfirm] = useState<"delete" | null>(null);

  const users = useInfiniteQuery({
    queryKey: ["users", tenant, q, status, deleted, sort.key, sort.dir],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/users", {
        params: {
          path: { slug: tenant },
          query: { search: q || undefined, status: status || undefined, include_deleted: deleted || undefined, sort: sort.key as Sort, dir: sort.dir, cursor: pageParam, limit: 100 },
        },
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
  const chosen = rows.filter((u) => selected.has(u.id));

  const act = async (what: "enable" | "disable" | "delete") => {
    const path = (id: string) => ({ slug: tenant, user: id });
    const result = await runBulk(chosen, async (u) => {
      const r =
        what === "delete"
          ? await client.DELETE("/admin/tenants/{slug}/users/{user}", { params: { path: path(u.id) } })
          : await client.PATCH("/admin/tenants/{slug}/users/{user}", { params: { path: path(u.id) }, body: { status: what === "disable" ? "disabled" : "active" } as UserUpdate });
      if (r.error) throw new Error(r.error.detail ?? r.error.title);
    });
    toast(bulkToast(result, what === "delete" ? "deleted" : what === "disable" ? "disabled" : "enabled", ["user", "users"]));
    setSelected(new Set());
    await qc.invalidateQueries({ queryKey: ["users", tenant] });
  };

  const columns: Column<Row>[] = [
    {
      key: "username",
      header: "User",
      width: "minmax(12rem, 2fr)",
      sortable: true,
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
      sortable: true,
      cell: (u) => (
        <span className="truncate text-muted">
          {u.email ?? "—"}
          {u.email && !u.email_verified && <span className="ms-1.5 text-caption text-warn">unverified</span>}
        </span>
      ),
    },
    { key: "status", header: "Status", width: "6.5rem", sortable: true, cell: (u) => <Status tone={statusTone(u.status)}>{STATUS_LABELS[u.status]}</Status> },
    {
      key: "last_login",
      header: "Last sign-in",
      width: "8.5rem",
      sortable: true,
      cell: (u) => (
        <span className={`inline-flex items-center gap-1.5 font-mono text-caption ${isFresh(u.last_login_at) ? "text-ink-2" : "text-muted"}`}>
          <i aria-hidden className={`size-1.5 rounded-full ${isFresh(u.last_login_at) ? "bg-ok" : "bg-line-strong"}`} />
          {u.last_login_at ? fmtWhen(u.last_login_at) : "Never"}
        </span>
      ),
    },
    { key: "second_step", header: "Second step", width: "6.5rem", cell: (u) => <SecondStep step={u.second_step ?? null} /> },
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
        <ChipSelect label="Status" value={status} onChange={(v) => params.set({ status: v })}>
          <option value="">any</option>
          {STATUSES.filter((s) => s !== "deleted").map((s) => (
            <option key={s} value={s}>
              {STATUS_LABELS[s]}
            </option>
          ))}
        </ChipSelect>
        <ChipToggle label="Include deleted" checked={deleted} onChange={(v) => params.set({ deleted: v ? "1" : "" })} />
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
          minWidth="48rem"
          sort={{ state: sort, onChange: (s) => params.set({ sort: s.key === "created" && s.dir === "asc" ? "" : s.key, dir: s.dir === "asc" ? "" : "desc" }) }}
          selection={writer ? { selected, onChange: setSelected, name: (u) => u.username } : undefined}
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
          footer={<ListFooter mode="auto" count={rows.length} hasMore={Boolean(hasNextPage)} loading={isFetchingNextPage} note={sort.key !== "created" || sort.dir !== "asc" ? `sorted by ${sort.key.replace("_", " ")}${sort.dir === "desc" ? ", descending" : ""}` : undefined} />}
        />
      )}
      <BulkBar count={chosen.length} label="Selected users" onClear={() => setSelected(new Set())}>
        <button type="button" className={bulkButtonClass()} onClick={() => void act("enable")}>
          Enable
        </button>
        <button type="button" className={bulkButtonClass()} onClick={() => void act("disable")}>
          Disable
        </button>
        <button type="button" className={bulkButtonClass(true)} onClick={() => setConfirm("delete")}>
          Delete
        </button>
      </BulkBar>
      <ConfirmDialog
        open={confirm === "delete"}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Delete ${chosen.length} ${chosen.length === 1 ? "user" : "users"}?`}
        description="Each account is soft-deleted: its sessions and devices end at once; it can be purged later."
        confirmLabel="Delete"
        onConfirm={() => act("delete")}
      />
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
