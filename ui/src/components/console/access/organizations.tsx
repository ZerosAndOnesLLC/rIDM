"use client";

import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Briefcase, Plus } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Field, TextInput } from "@/components/console/form";
import { Badge, Button, Card, PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { href } from "@/lib/console/access";
import { useDebounced } from "@/lib/console/hooks";
import { useConsole } from "@/lib/console/session";
import { CreateDialog, ErrorLine, Split } from "./common";
import { OrganizationDetailView, P_WRITE } from "./organization-detail";

export function OrganizationsPage({ tenant, selected }: { tenant: string; selected: string | null }) {
  const { client, can, confinedToOrg, org } = useConsole();
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim(), 200);
  // An administrator whose `ridm:orgs:read` comes from a grant inside one
  // organization cannot list the tenant's others; the page opens theirs.
  const confined = confinedToOrg("ridm:orgs:read") && !!org;
  const list = useInfiniteQuery({
    queryKey: ["organizations", tenant, q],
    enabled: !confined,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error } = await client.GET("/admin/tenants/{slug}/organizations", {
        params: { path: { slug: tenant }, query: { ...(q ? { search: q } : {}), ...(pageParam ? { cursor: pageParam } : {}) } },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];

  if (confined) {
    return (
      <>
        <PageHeader
          title={org.display_name}
          sub="The organization you administer. Its members, domains, roles and invitations are yours to manage."
        />
        <OrganizationDetailView key={org.id} tenant={tenant} id={org.id} />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Organizations"
        sub="Customers, business units or teams inside this tenant. Members choose one when they sign in."
        actions={
          can(P_WRITE) ? (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" aria-hidden />
              New organization
            </Button>
          ) : undefined
        }
      />
      <Split
        list={
          <Card title="Organizations">
            <TextInput
              aria-label="Search organizations"
              placeholder="Search…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {list.isPending ? (
              <Spinner label="Loading…" />
            ) : list.isError ? (
              <ErrorLine error={list.error} />
            ) : items.length === 0 ? (
              <p className="mt-3 text-[0.875rem] text-muted">
                {q ? "Nothing matches." : "No organizations yet."}
              </p>
            ) : (
              <ul className="mt-3 flex flex-col">
                {items.map((o) => (
                  <li key={o.id}>
                    <Link
                      href={href("organizations", tenant, { org: o.id })}
                      aria-current={o.id === selected ? "page" : undefined}
                      className={`flex items-center gap-2 rounded-[var(--radius)] px-2 py-1.5 text-[0.875rem] ${o.id === selected ? "bg-[color-mix(in_oklab,var(--accent)_12%,transparent)] text-ink" : "text-ink hover:bg-ground"}`}
                    >
                      <Briefcase className="size-3.5 shrink-0 text-muted" aria-hidden />
                      <span className="truncate">{o.display_name}</span>
                      {o.status === "disabled" && <Badge>disabled</Badge>}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
            {list.hasNextPage && (
              <div className="mt-2 text-center">
                <Button onClick={() => void list.fetchNextPage()} disabled={list.isFetchingNextPage}>
                  {list.isFetchingNextPage ? "Loading…" : "Load more"}
                </Button>
              </div>
            )}
          </Card>
        }
        detail={
          selected ? (
            <OrganizationDetailView key={selected} tenant={tenant} id={selected} />
          ) : (
            <p className="text-[0.9rem] text-muted">Choose an organization.</p>
          )
        }
      />
      <CreateOrganization tenant={tenant} open={creating} onOpenChange={setCreating} />
    </>
  );
}

function CreateOrganization({
  tenant,
  open,
  onOpenChange,
}: {
  tenant: string;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const { client } = useConsole();
  const qc = useQueryClient();
  const router = useRouter();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  // The slug follows the name until it is edited by hand.
  const [slugEdited, setSlugEdited] = useState(false);
  const suggested = slugEdited
    ? slug
    : name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 63);
  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await client.POST("/admin/tenants/{slug}/organizations", {
        params: { path: { slug: tenant } },
        body: { slug: suggested, display_name: name.trim(), description: null, attributes: null },
      });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
    onSuccess: (o) => {
      void qc.invalidateQueries({ queryKey: ["organizations", tenant] });
      setName("");
      setSlug("");
      setSlugEdited(false);
      onOpenChange(false);
      router.push(href("organizations", tenant, { org: o.id }));
    },
  });
  return (
    <CreateDialog
      open={open}
      onOpenChange={onOpenChange}
      title="New organization"
      submitLabel="Create organization"
      pending={create.isPending}
      error={create.error?.message ?? null}
      onSubmit={() => name.trim() && suggested && create.mutate()}
    >
      <Field label="Name">
        {(id) => (
          <TextInput
            id={id}
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            required
          />
        )}
      </Field>
      <Field label="Slug" hint="Lowercase letters, digits and hyphens. Cannot be changed lightly: it may appear in requests.">
        {(id, by) => (
          <TextInput
            id={id}
            aria-describedby={by}
            value={suggested}
            onChange={(e) => {
              setSlugEdited(true);
              setSlug(e.target.value);
            }}
            required
          />
        )}
      </Field>
    </CreateDialog>
  );
}
