"use client";

import { useInfiniteQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useState } from "react";
import { TextInput } from "@/components/console/form";
import { Button } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import type { Member } from "@/lib/console/access";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { ErrorLine } from "./common";

/** Whose members: a group's or an organization's. */
export type MembersOf = { kind: "group"; id: string } | { kind: "organization"; id: string };

/** The query key prefix of a member list, for invalidation after a change. */
export function membersKey(tenant: string, of: MembersOf) {
  return [of.kind, tenant, of.id, "members"] as const;
}

/**
 * A group's or organization's direct members, a page at a time in the order
 * they joined, with a prefix filter on username or email.
 */
export function MemberList({
  tenant,
  of,
  empty,
  row,
}: {
  tenant: string;
  of: MembersOf;
  /** Shown when there are no members at all (not when the filter hides them). */
  empty: ReactNode;
  row: (m: Member) => ReactNode;
}) {
  const { client } = useConsole();
  const [filter, setFilter] = useState("");
  const q = useDebounced(filter.trim(), 200);
  const pages = useInfiniteQuery({
    queryKey: [...membersKey(tenant, of), q],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const query = { ...(q ? { search: q } : {}), ...(pageParam ? { cursor: pageParam } : {}) };
      const { data, error } =
        of.kind === "group"
          ? await client.GET("/admin/tenants/{slug}/groups/{group}/members", {
              params: { path: { slug: tenant, group: of.id }, query },
            })
          : await client.GET("/admin/tenants/{slug}/organizations/{org}/members", {
              params: { path: { slug: tenant, org: of.id }, query },
            });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const members = pages.data?.pages.flatMap((p) => p.items) ?? [];
  const filtering = q !== "";

  return (
    <>
      {(filtering || members.length > 0) && (
        <TextInput
          aria-label="Filter members"
          placeholder="Filter by username or email…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="mb-2"
        />
      )}
      {pages.isPending ? (
        <Spinner label="Loading members…" />
      ) : pages.isError ? (
        <ErrorLine error={pages.error} />
      ) : members.length === 0 ? (
        filtering ? <p className="text-[0.875rem] text-muted">No member matches.</p> : empty
      ) : (
        <ul className="divide-y divide-line">{members.map((m) => row(m))}</ul>
      )}
      {pages.hasNextPage && (
        <div className="mt-2 text-center">
          <Button onClick={() => void pages.fetchNextPage()} disabled={pages.isFetchingNextPage}>
            {pages.isFetchingNextPage ? "Loading…" : "Load more"}
          </Button>
        </div>
      )}
    </>
  );
}
