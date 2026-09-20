"use client";

import { useQuery } from "@tanstack/react-query";
import { AppWindow, UserRound } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useDebounced } from "@/lib/console/hooks";
import { allNavItems, consoleHref, navVisible } from "@/lib/console/nav";
import { useConsole } from "@/lib/console/session";
import { Picker, type PickerItem } from "./picker";
import { Kbd } from "./ui";

/**
 * Global search (⌘K): console pages the administrator may open, plus users
 * and clients of the current tenant by prefix.
 */
export function CommandPalette({ open, onOpenChange, tenant }: { open: boolean; onOpenChange: (o: boolean) => void; tenant: string | null }) {
  const { client, can, canInOrg, me } = useConsole();
  const router = useRouter();
  const [query, setQuery] = useState("");
  const q = useDebounced(query.trim(), 150);
  const close = (o: boolean) => {
    if (!o) setQuery("");
    onOpenChange(o);
  };

  const searching = open && q.length >= 2 && Boolean(tenant);
  const users = useQuery({
    queryKey: ["palette", "users", tenant, q],
    enabled: searching && can("ridm:users:read"),
    queryFn: async () => {
      const { data } = await client.GET("/admin/tenants/{slug}/users", {
        params: { path: { slug: tenant! }, query: { search: q, limit: 5 } },
      });
      return data?.items ?? [];
    },
  });
  const clients = useQuery({
    queryKey: ["palette", "clients", tenant, q],
    enabled: searching && can("ridm:clients:read"),
    queryFn: async () => {
      const { data } = await client.GET("/admin/tenants/{slug}/clients", {
        params: { path: { slug: tenant! }, query: { search: q, limit: 5 } },
      });
      return data?.items ?? [];
    },
  });

  const go = (href: string) => router.push(href);
  const lower = q.toLowerCase();
  const items: PickerItem[] = [
    ...allNavItems()
      .filter(
        (n) =>
          navVisible(n, { can, canInOrg, global: me?.scope === "global" }) &&
          (!lower || n.label.toLowerCase().includes(lower)),
      )
      .map<PickerItem>((n) => ({
        id: `page:${n.href}`,
        group: "Pages",
        icon: <n.icon className="size-4" aria-hidden />,
        label: n.label,
        trailing: n.key ? (
          <span className="flex gap-1">
            <Kbd>g</Kbd>
            <Kbd>{n.key}</Kbd>
          </span>
        ) : undefined,
        onSelect: () => go(consoleHref(n.href, tenant)),
      })),
    ...(users.data ?? []).map<PickerItem>((u) => ({
      id: `user:${u.id}`,
      group: "Users",
      icon: <UserRound className="size-4" aria-hidden />,
      label: u.username,
      hint: u.email && u.email !== u.username ? u.email : undefined,
      onSelect: () => go(`/console/users/?tenant=${encodeURIComponent(tenant!)}&user=${u.id}`),
    })),
    ...(clients.data ?? []).map<PickerItem>((c) => ({
      id: `client:${c.id}`,
      group: "Clients",
      icon: <AppWindow className="size-4" aria-hidden />,
      label: c.name,
      hint: c.client_id,
      onSelect: () => go(`/console/clients/?tenant=${encodeURIComponent(tenant!)}&client=${c.id}`),
    })),
  ];

  return (
    <Picker
      open={open}
      onOpenChange={close}
      title="Search"
      placeholder={tenant ? `Search pages, users and clients in ${tenant}…` : "Search pages…"}
      query={query}
      onQueryChange={setQuery}
      items={items}
      loading={users.isFetching || clients.isFetching}
      empty={q.length < 2 ? "Type at least two characters to search users and clients." : "Nothing matches."}
    />
  );
}

/** Tenant switcher for global administrators. */
export function TenantSwitcher({
  open,
  onOpenChange,
  current,
  onPick,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  current: string | null;
  onPick: (slug: string) => void;
}) {
  const { client } = useConsole();
  const [query, setQuery] = useState("");
  const close = (o: boolean) => {
    if (!o) setQuery("");
    onOpenChange(o);
  };
  const tenants = useQuery({
    queryKey: ["tenants", "all"],
    enabled: open,
    staleTime: 60_000,
    queryFn: async () => {
      const out: { slug: string; display_name: string; status: string }[] = [];
      let cursor: string | undefined;
      for (let page = 0; page < 10; page += 1) {
        const { data } = await client.GET("/admin/tenants", { params: { query: { limit: 100, cursor } } });
        if (!data) break;
        out.push(...data.items);
        if (!data.next_cursor) break;
        cursor = data.next_cursor;
      }
      return out;
    },
  });
  const lower = query.trim().toLowerCase();
  const items: PickerItem[] = (tenants.data ?? [])
    .filter((t) => !lower || t.slug.includes(lower) || t.display_name.toLowerCase().includes(lower))
    .map((t) => ({
      id: t.slug,
      group: "Tenants",
      label: t.display_name,
      hint: t.slug,
      trailing: t.slug === current ? <span className="text-[0.75rem]">current</span> : t.status === "disabled" ? <span className="text-[0.75rem]">disabled</span> : undefined,
      onSelect: () => onPick(t.slug),
    }));
  return (
    <Picker
      open={open}
      onOpenChange={close}
      title="Switch tenant"
      placeholder="Find a tenant…"
      query={query}
      onQueryChange={setQuery}
      items={items}
      loading={tenants.isFetching}
      empty={tenants.isError ? "Tenants could not be loaded." : "No tenant matches."}
    />
  );
}
