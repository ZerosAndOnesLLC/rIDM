"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { Bell, Briefcase, Building2, ChevronsUpDown, LogOut, Menu, Search, ShieldCheck, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { Breadcrumbs } from "@/components/base/breadcrumbs";
import { ThemeSwitch } from "@/components/base/theme-switch";
import { Spinner } from "@/components/ui";
import { useNavCounts } from "@/lib/console/counts";
import { fmtNumber, initials } from "@/lib/console/format";
import { NAV, PAGE_TITLES, allNavItems, consoleHref, navVisible } from "@/lib/console/nav";
import { useConsole } from "@/lib/console/session";
import { modKey, useShortcuts } from "@/lib/console/shortcuts";
import { useConsoleTenant } from "@/lib/console/tenant";
import { useTenantAppearance, useTenantPublic } from "@/lib/theme/use-tenant-appearance";
import { CommandPalette, TenantSwitcher } from "./palette";
import { SignIn } from "./sign-in";
import { Avatar, IconButton, Kbd, Modal } from "./ui";

/**
 * Gate plus frame for every console page: the sign-in card while signed
 * out, otherwise the command bar, sidebar and the page. The callback page
 * renders bare because it is what produces the session.
 */
export function ConsoleShell({ children }: { children: ReactNode }) {
  const { status } = useConsole();
  const pathname = usePathname();
  if (pathname.startsWith("/console/callback")) return <>{children}</>;
  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner label="Loading…" />
      </div>
    );
  }
  if (status === "signed_out") return <SignIn />;
  return <Frame>{children}</Frame>;
}

/**
 * The frame (design/README.md "Layout"): a command bar across the top
 * (wordmark, tenant switcher, search, theme), the sidebar on the tinted
 * ground with counts, and the page in an elevated sheet. The skins retune
 * it through tokens (globals.css); below `md` the sidebar is a drawer and
 * the sheet loses its inset.
 */
function Frame({ children }: { children: ReactNode }) {
  const { me, signOut, can, canInOrg } = useConsole();
  const tenant = useConsoleTenant();
  useTenantAppearance(tenant);
  const router = useRouter();
  const pathname = usePathname();
  const [palette, setPalette] = useState(false);
  const [tenants, setTenants] = useState(false);
  const [help, setHelp] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const global = me?.scope === "global";

  const items = allNavItems().filter((n) => navVisible(n, { can, canInOrg, global }));
  const current = items.find((n) => n.href === pathname) ?? items.find((n) => pathname.startsWith(n.href) && n.href !== "/console/");
  const group = current ? NAV.find((g) => g.items.includes(current)) : undefined;
  const title = current?.label ?? PAGE_TITLES[pathname] ?? "Console";
  const { attentionTotal } = useNavCounts(tenant);
  const tenantName = useTenantPublic(tenant)?.display_name ?? null;

  useShortcuts({
    palette: () => setPalette(true),
    tenants: global ? () => setTenants(true) : undefined,
    help: () => setHelp(true),
    go: (key) => {
      const hit = items.find((n) => n.key === key);
      if (!hit) return false;
      router.push(consoleHref(hit.href, tenant));
      return true;
    },
  });

  const switchTenant = (slug: string) => {
    setTenants(false);
    setDrawer(false);
    router.push(consoleHref(current?.href ?? "/console/", slug));
  };

  const sidebar = <Sidebar tenant={tenant} global={global} pathname={pathname} onNavigate={() => setDrawer(false)} me={me} onSignOut={signOut} />;

  return (
    <div className="min-h-screen md:grid md:grid-cols-[14.75rem_minmax(0,1fr)] md:grid-rows-[3.25rem_minmax(0,1fr)]">
      <a href="#main" className="skip-link">
        Skip to content
      </a>

      <header className="console-bar sticky top-0 z-30 flex h-[3.25rem] items-center gap-2 px-2.5 sm:gap-3 sm:px-3.5 md:col-span-2">
        <Dialog.Root open={drawer} onOpenChange={setDrawer}>
          <Dialog.Trigger asChild>
            <IconButton label="Open navigation" className="text-bar-muted hover:bg-[var(--bar-field)] hover:text-bar-ink md:hidden">
              <Menu className="size-5" aria-hidden />
            </IconButton>
          </Dialog.Trigger>
          <Dialog.Portal>
            <Dialog.Overlay className="fixed inset-0 z-40 bg-[rgba(8,10,14,0.45)] md:hidden" />
            <Dialog.Content className="console-rail console-drawer fixed inset-y-0 start-0 z-50 flex w-[17rem] max-w-[85vw] flex-col md:hidden">
              <Dialog.Title className="sr-only">Navigation</Dialog.Title>
              <Dialog.Description className="sr-only">Console sections</Dialog.Description>
              <Dialog.Close asChild>
                <IconButton label="Close navigation" className="absolute end-2 top-2.5">
                  <X className="size-4" aria-hidden />
                </IconButton>
              </Dialog.Close>
              {sidebar}
            </Dialog.Content>
          </Dialog.Portal>
        </Dialog.Root>

        <Link href={consoleHref("/console/", tenant)} className="flex shrink-0 items-center gap-2 no-underline md:w-[13.5rem]">
          <span aria-hidden className="flex size-6 items-center justify-center rounded-[7px] bg-[linear-gradient(135deg,var(--accent-400),var(--accent-700))] text-white shadow-[inset_0_0_0_1px_rgba(255,255,255,0.08)]">
            <ShieldCheck className="size-3.5" />
          </span>
          <span className="font-display text-[1.0625rem] font-bold tracking-[-0.02em] text-bar-ink max-md:sr-only">rIDM</span>
        </Link>

        <div className="flex min-w-0 flex-1 items-center gap-2 md:max-w-3xl">
          {global ? (
            <button
              type="button"
              onClick={() => setTenants(true)}
              aria-label={`Tenant: ${tenant ?? "none"}. Switch tenant`}
              className="flex h-[2.125rem] shrink-0 items-center gap-2 rounded-full border border-[var(--bar-line)] bg-[var(--bar-field)] ps-1 pe-2.5 text-bar-ink hover:brightness-125"
            >
              <TenantMark name={tenantName ?? tenant ?? "?"} />
              <span className="hidden min-w-0 items-baseline gap-1.5 sm:flex">
                <span className="truncate text-small font-semibold">{tenantName ?? tenant ?? "—"}</span>
                {tenantName && <span className="font-mono text-caption text-bar-muted">{tenant}</span>}
              </span>
              <ChevronsUpDown className="size-3.5 shrink-0 text-bar-muted" aria-hidden />
            </button>
          ) : (
            <span className="flex h-[2.125rem] shrink-0 items-center gap-2 rounded-full border border-[var(--bar-line)] bg-[var(--bar-field)] ps-1 pe-2.5 text-bar-ink">
              <TenantMark name={tenantName ?? tenant ?? "?"} />
              <span className="sr-only">Tenant:</span>
              <span className="hidden min-w-0 items-baseline gap-1.5 sm:flex">
                <span className="truncate text-small font-semibold">{tenantName ?? tenant ?? "—"}</span>
                {tenantName && <span className="font-mono text-caption text-bar-muted">{tenant}</span>}
              </span>
            </span>
          )}
          <button
            type="button"
            aria-label="Search"
            onClick={() => setPalette(true)}
            className="flex h-[2.125rem] min-w-0 flex-1 items-center gap-2 rounded-full border border-[var(--bar-line)] bg-[var(--bar-field)] px-3 text-small text-bar-muted hover:brightness-125 hover:text-bar-ink"
          >
            <Search className="size-4 shrink-0" aria-hidden />
            <span className="hidden truncate sm:inline">Search users, clients, pages…</span>
            <span className="ms-auto hidden gap-1 sm:flex" aria-hidden>
              <kbd className="border-[var(--bar-line)] bg-transparent text-bar-muted">{modKey()}</kbd>
              <kbd className="border-[var(--bar-line)] bg-transparent text-bar-muted">K</kbd>
            </span>
          </button>
        </div>

        <div className="ms-auto flex shrink-0 items-center gap-1.5">
          <ThemeSwitch surface="bar" />
          <Link
            href={`${consoleHref("/console/", tenant)}#attention`}
            aria-label={attentionTotal > 0 ? `${attentionTotal} ${attentionTotal === 1 ? "thing needs" : "things need"} attention` : "Nothing needs attention"}
            title={attentionTotal > 0 ? `${attentionTotal} ${attentionTotal === 1 ? "thing needs" : "things need"} attention` : "Nothing needs attention"}
            className="relative hidden size-8 items-center justify-center rounded-full text-bar-muted no-underline hover:bg-[var(--bar-field)] hover:text-bar-ink sm:flex"
          >
            <Bell className="size-4" aria-hidden />
            {attentionTotal > 0 && <span aria-hidden className="absolute end-1.5 top-1.5 size-[7px] rounded-full bg-[var(--contrast-500)] shadow-[0_0_0_2px_var(--bar)]" />}
          </Link>
        </div>
      </header>

      {/* dvh, not vh: iPad Safari measures vh with its toolbar hidden, which would put the bottom of the sidebar under the toolbar. */}
      <aside className="console-rail sticky top-[3.25rem] hidden h-[calc(100dvh-3.25rem)] flex-col overflow-y-auto md:flex">{sidebar}</aside>

      <div className="console-content flex min-h-[calc(100dvh-3.25rem)] min-w-0 flex-col">
        <div className="console-sheet flex flex-1 flex-col">
          <div className="flex items-center gap-3 px-4 pt-3.5 sm:px-6">
            <Breadcrumbs items={group?.title ? [{ label: group.title }, { label: title }] : [{ label: title }]} />
          </div>
          <main id="main" tabIndex={-1} className="flex-1 px-4 pb-8 pt-3 sm:px-6">
            {children}
          </main>
        </div>
      </div>

      <CommandPalette open={palette} onOpenChange={setPalette} tenant={tenant} />
      {global && <TenantSwitcher open={tenants} onOpenChange={setTenants} current={tenant} onPick={switchTenant} />}
      <ShortcutsHelp open={help} onOpenChange={setHelp} global={global} />
    </div>
  );
}

/** The tenant's round mark: its initial on the primary → contrast gradient. */
function TenantMark({ name }: { name: string }) {
  return (
    <span aria-hidden className="flex size-6 items-center justify-center rounded-full bg-[linear-gradient(135deg,var(--accent-500),var(--contrast-500))] text-[0.6875rem] font-bold text-white">
      {initials(name).slice(0, 1)}
    </span>
  );
}

function Sidebar({ tenant, global, pathname, onNavigate, me, onSignOut }: { tenant: string | null; global: boolean; pathname: string; onNavigate: () => void; me: ReturnType<typeof useConsole>["me"]; onSignOut: () => void }) {
  const { can, canInOrg, org } = useConsole();
  const { counts, attention } = useNavCounts(tenant);
  return (
    <>
      {org && (
        <div className="px-3 pt-3">
          <div className="flex items-center gap-2.5 rounded-[var(--radius)] border border-[var(--rail-line)] bg-[var(--rail-hover)] px-3 py-2">
            <Briefcase className="size-4 shrink-0 text-[var(--rail-muted)]" aria-hidden />
            <span className="min-w-0 flex-1">
              <span className="block text-tiny text-[var(--rail-hint)]">Organization</span>
              <span className="block truncate text-small font-medium">{org.display_name}</span>
            </span>
          </div>
        </div>
      )}
      {!global && (
        <div className="px-3 pt-3 md:hidden">
          <div className="flex items-center gap-2.5 rounded-[var(--radius)] border border-[var(--rail-line)] bg-[var(--rail-hover)] px-3 py-2">
            <Building2 className="size-4 shrink-0 text-[var(--rail-muted)]" aria-hidden />
            <span className="min-w-0 flex-1">
              <span className="block text-tiny text-[var(--rail-hint)]">Tenant</span>
              <span className="block truncate text-small font-medium">{tenant ?? "—"}</span>
            </span>
          </div>
        </div>
      )}

      <nav aria-label="Console" className="console-nav flex-1 overflow-y-auto px-2.5 py-2.5">
        {NAV.map((group, gi) => {
          const visible = group.items.filter((n) => navVisible(n, { can, canInOrg, global }));
          if (visible.length === 0) return null;
          return (
            <div key={group.title ?? gi} className="mb-2">
              {group.title && <div className="nav-group mx-2.5 mb-1 mt-3 text-tiny font-semibold tracking-[0.02em]">{group.title}</div>}
              <ul className="flex flex-col gap-0.5">
                {visible.map((n) => {
                  const active = pathname === n.href;
                  const count = n.count ? counts[n.count] : undefined;
                  const hot = n.count ? attention[n.count] : undefined;
                  return (
                    <li key={n.href}>
                      <Link
                        href={consoleHref(n.href, tenant)}
                        aria-current={active ? "page" : undefined}
                        onClick={onNavigate}
                        className="grid h-8 grid-cols-[1rem_minmax(0,1fr)_auto] items-center gap-2.5 rounded-[var(--radius)] px-2.5 text-small no-underline"
                      >
                        <n.icon className="size-[0.9375rem] shrink-0" aria-hidden />
                        <span className="truncate">{n.label}</span>
                        {hot ? (
                          <span className="nav-count hot">{`${fmtNumber(hot)} pending`}</span>
                        ) : count !== undefined ? (
                          <span className="nav-count">{fmtNumber(count)}</span>
                        ) : n.key ? (
                          <span className="nav-hint" aria-hidden>
                            g {n.key}
                          </span>
                        ) : null}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </nav>

      <div className="border-t border-[var(--rail-line)] p-3">
        <div className="flex items-center gap-2.5 px-1">
          <Avatar name={me?.username ?? "?"} />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-small font-medium" data-testid="me-username">
              {me?.username}
            </span>
            <span className="block truncate text-caption text-[var(--rail-muted)]">{global ? "Global administrator" : `Administrator of ${me?.tenant_slug ?? ""}`}</span>
          </span>
          <IconButton label="Sign out" onClick={onSignOut} className="text-[var(--rail-muted)] hover:bg-[var(--rail-hover)] hover:text-[var(--rail-active-ink)]">
            <LogOut className="size-4" aria-hidden />
          </IconButton>
        </div>
      </div>
    </>
  );
}

function ShortcutsHelp({ open, onOpenChange, global }: { open: boolean; onOpenChange: (o: boolean) => void; global: boolean }) {
  const mod = modKey();
  const rows: { keys: string[]; what: string }[] = [
    { keys: [mod, "K"], what: "Search pages, users and clients" },
    { keys: ["/"], what: "Search" },
    ...(global ? [{ keys: ["t"], what: "Switch tenant" }] : []),
    ...allNavItems()
      .filter((n) => n.key)
      .map((n) => ({ keys: ["g", n.key!], what: `Go to ${n.label.toLowerCase()}` })),
    { keys: ["?"], what: "This help" },
    { keys: ["Esc"], what: "Close a dialog" },
  ];
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Keyboard shortcuts" description="Single keys work when no field has focus.">
      <dl className="px-5 pb-5 pt-3">
        {rows.map((r) => (
          <div key={r.what} className="flex items-center justify-between gap-4 py-2 text-body not-last:border-b not-last:border-line">
            <dt className="text-ink">{r.what}</dt>
            <dd className="flex gap-1">
              {r.keys.map((k, i) => (
                <Kbd key={i}>{k}</Kbd>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </Modal>
  );
}
