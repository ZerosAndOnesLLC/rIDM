"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { Building2, ChevronsUpDown, LogOut, Menu, Monitor, Moon, Search, ShieldCheck, Sun, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { Spinner } from "@/components/ui";
import { NAV, allNavItems, consoleHref } from "@/lib/console/nav";
import { useConsole } from "@/lib/console/session";
import { modKey, useShortcuts } from "@/lib/console/shortcuts";
import { useConsoleTenant } from "@/lib/console/tenant";
import { useTheme, type Theme } from "@/lib/console/theme";
import { CommandPalette, TenantSwitcher } from "./palette";
import { SignIn } from "./sign-in";
import { IconButton, Kbd, Modal } from "./ui";

/**
 * Gate plus frame for every console page: the sign-in card while signed
 * out, otherwise sidebar, top bar and the page. The callback page renders
 * bare because it is what produces the session.
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

function Frame({ children }: { children: ReactNode }) {
  const { me, signOut, can } = useConsole();
  const tenant = useConsoleTenant();
  const router = useRouter();
  const pathname = usePathname();
  const [palette, setPalette] = useState(false);
  const [tenants, setTenants] = useState(false);
  const [help, setHelp] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const global = me?.scope === "global";

  const items = allNavItems().filter((n) => can(n.permission) && (!n.global || global));
  const current = items.find((n) => n.href === pathname) ?? items.find((n) => pathname.startsWith(n.href) && n.href !== "/console/");

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

  const sidebar = (
    <Sidebar
      tenant={tenant}
      global={global}
      onSwitch={() => setTenants(true)}
      pathname={pathname}
      onNavigate={() => setDrawer(false)}
      me={me}
      onSignOut={signOut}
    />
  );

  return (
    <div className="min-h-screen md:grid md:grid-cols-[15.5rem_minmax(0,1fr)]">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-screen flex-col border-e border-line bg-paper md:flex">{sidebar}</aside>

      <div className="flex min-h-screen flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-line bg-paper/90 px-3 backdrop-blur sm:px-5">
          <Dialog.Root open={drawer} onOpenChange={setDrawer}>
            <Dialog.Trigger asChild>
              <IconButton label="Open navigation" className="md:hidden">
                <Menu className="size-5" aria-hidden />
              </IconButton>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 z-40 bg-black/40 md:hidden" />
              <Dialog.Content className="fixed inset-y-0 start-0 z-50 flex w-[17rem] max-w-[85vw] flex-col border-e border-line bg-paper md:hidden">
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
          <p className="min-w-0 flex-1 truncate text-[0.9375rem] font-medium text-ink">{current?.label ?? "Console"}</p>
          <button
            type="button"
            onClick={() => setPalette(true)}
            className="flex min-h-9 items-center gap-2 rounded-[var(--radius)] border border-line bg-ground px-3 text-[0.875rem] text-muted hover:text-ink"
          >
            <Search className="size-4" aria-hidden />
            <span className="hidden sm:inline">Search…</span>
            <span className="hidden gap-1 sm:flex" aria-hidden>
              <Kbd>{modKey()}</Kbd>
              <Kbd>K</Kbd>
            </span>
          </button>
          <ThemeSwitch />
        </header>
        <main id="main" tabIndex={-1} className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <div className="mx-auto w-full max-w-6xl">{children}</div>
        </main>
      </div>

      <CommandPalette open={palette} onOpenChange={setPalette} tenant={tenant} />
      {global && <TenantSwitcher open={tenants} onOpenChange={setTenants} current={tenant} onPick={switchTenant} />}
      <ShortcutsHelp open={help} onOpenChange={setHelp} global={global} />
    </div>
  );
}

function Sidebar({
  tenant,
  global,
  onSwitch,
  pathname,
  onNavigate,
  me,
  onSignOut,
}: {
  tenant: string | null;
  global: boolean;
  onSwitch: () => void;
  pathname: string;
  onNavigate: () => void;
  me: ReturnType<typeof useConsole>["me"];
  onSignOut: () => void;
}) {
  const { can } = useConsole();
  return (
    <>
      <div className="flex h-14 items-center gap-2.5 px-4">
        <span aria-hidden className="flex size-8 items-center justify-center rounded-lg bg-accent text-accent-ink">
          <ShieldCheck className="size-[1.125rem]" />
        </span>
        <span className="text-[1rem] font-semibold text-ink">rIDM</span>
      </div>

      <div className="px-3 pb-2">
        {global ? (
          <button
            type="button"
            onClick={onSwitch}
            aria-label={`Tenant: ${tenant ?? "none"}. Switch tenant`}
            className="flex w-full items-center gap-2.5 rounded-[var(--radius)] border border-line bg-ground px-3 py-2 text-start hover:border-muted/60"
          >
            <Building2 className="size-4 shrink-0 text-muted" aria-hidden />
            <span className="min-w-0 flex-1">
              <span className="block text-[0.6875rem] uppercase tracking-wide text-muted">Tenant</span>
              <span className="block truncate text-[0.875rem] font-medium text-ink">{tenant ?? "—"}</span>
            </span>
            <ChevronsUpDown className="size-4 shrink-0 text-muted" aria-hidden />
          </button>
        ) : (
          <div className="flex items-center gap-2.5 rounded-[var(--radius)] border border-line bg-ground px-3 py-2">
            <Building2 className="size-4 shrink-0 text-muted" aria-hidden />
            <span className="min-w-0 flex-1">
              <span className="block text-[0.6875rem] uppercase tracking-wide text-muted">Tenant</span>
              <span className="block truncate text-[0.875rem] font-medium text-ink">{tenant ?? "—"}</span>
            </span>
          </div>
        )}
      </div>

      <nav aria-label="Console" className="console-nav flex-1 overflow-y-auto px-3 py-2">
        {NAV.map((group, gi) => {
          const visible = group.items.filter((n) => can(n.permission) && (!n.global || global));
          if (visible.length === 0) return null;
          return (
            <div key={group.title ?? gi} className="mb-3">
              {group.title && <div className="px-3 pb-1 pt-2 text-[0.6875rem] font-semibold uppercase tracking-wide text-muted">{group.title}</div>}
              <ul className="flex flex-col gap-0.5">
                {visible.map((n) => {
                  const active = pathname === n.href;
                  return (
                    <li key={n.href}>
                      <Link
                        href={consoleHref(n.href, tenant)}
                        aria-current={active ? "page" : undefined}
                        onClick={onNavigate}
                        className="flex items-center gap-2.5 rounded-[var(--radius)] px-3 py-2 text-[0.875rem] text-muted hover:bg-ground hover:text-ink"
                      >
                        <n.icon className="size-4 shrink-0" aria-hidden />
                        <span className="flex-1 truncate">{n.label}</span>
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </nav>

      <div className="border-t border-line p-3">
        <div className="flex items-center gap-2.5 px-1">
          <span aria-hidden className="flex size-8 shrink-0 items-center justify-center rounded-full bg-ground text-[0.8125rem] font-semibold text-ink">
            {(me?.username ?? "?").slice(0, 1).toUpperCase()}
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[0.875rem] font-medium text-ink" data-testid="me-username">
              {me?.username}
            </span>
            <span className="block truncate text-[0.75rem] text-muted">{global ? "Global administrator" : `Administrator of ${me?.tenant_slug ?? ""}`}</span>
          </span>
          <IconButton label="Sign out" onClick={onSignOut}>
            <LogOut className="size-4" aria-hidden />
          </IconButton>
        </div>
      </div>
    </>
  );
}

const THEMES: { value: Theme; label: string; icon: typeof Sun }[] = [
  { value: "system", label: "Follow system theme", icon: Monitor },
  { value: "light", label: "Light theme", icon: Sun },
  { value: "dark", label: "Dark theme", icon: Moon },
];

function ThemeSwitch() {
  const { theme, setTheme } = useTheme();
  return (
    <div role="group" aria-label="Theme" className="flex items-center gap-0.5 rounded-[var(--radius)] border border-line bg-ground p-0.5">
      {THEMES.map((t) => (
        <button
          key={t.value}
          type="button"
          aria-label={t.label}
          title={t.label}
          aria-pressed={theme === t.value}
          onClick={() => setTheme(t.value)}
          className={`flex size-8 items-center justify-center rounded-[calc(var(--radius)-2px)] ${
            theme === t.value ? "bg-paper text-ink shadow-sm" : "text-muted hover:text-ink"
          }`}
        >
          <t.icon className="size-4" aria-hidden />
        </button>
      ))}
    </div>
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
          <div key={r.what} className="flex items-center justify-between gap-4 py-2 text-[0.875rem] not-last:border-b not-last:border-line">
            <dt className="text-ink">{r.what}</dt>
            <dd className="flex gap-1">
              {r.keys.map((k) => (
                <Kbd key={k}>{k}</Kbd>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </Modal>
  );
}
