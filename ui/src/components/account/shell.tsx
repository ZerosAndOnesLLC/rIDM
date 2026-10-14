"use client";

import { LogOut, ShieldCheck, UserRoundCog } from "lucide-react";
import { ThemeSwitch } from "@/components/base/theme-switch";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useI18n } from "@/i18n/provider";
import { Alert, Button, Spinner, TextField } from "@/components/ui";
import { accountStore, useAccount } from "@/lib/account/session";
import { tenantBase } from "@/lib/api";
import { AuthError, isValidSlug, lastTenant } from "@/lib/console/auth";

/**
 * Gate plus frame for the account console: the sign-in card while signed
 * out, otherwise a header and the page. The callback page renders bare.
 */
export function AccountShell({ children }: { children: ReactNode }) {
  const { status } = useAccount();
  const { t } = useI18n();
  const pathname = usePathname();
  if (pathname.startsWith("/account/callback")) return <>{children}</>;
  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner label={t("common.loading")} />
      </div>
    );
  }
  if (status === "signed_out") return <SignIn />;
  return <Frame>{children}</Frame>;
}

/** The console's pages, in tab order. */
const PAGES = [
  { href: "/account/", key: "account.nav_profile" },
  { href: "/account/security/", key: "account.nav_security" },
  { href: "/account/organizations/", key: "account.nav_orgs" },
  { href: "/account/apps/", key: "account.nav_apps" },
  { href: "/account/approvals/", key: "account.nav_approvals" },
  { href: "/account/data/", key: "account.nav_data" },
] as const;

function Nav() {
  const { t } = useI18n();
  const pathname = usePathname();
  const here = pathname.endsWith("/") ? pathname : `${pathname}/`;
  return (
    <nav aria-label={t("account.nav_label")} className="mx-auto w-full max-w-4xl px-4 sm:px-5">
      <ul className="-mb-px flex gap-0.5 overflow-x-auto">
        {PAGES.map((p) => {
          const active = here === p.href;
          return (
            <li key={p.href}>
              <Link
                href={p.href}
                aria-current={active ? "page" : undefined}
                className={`inline-flex min-h-10 items-center whitespace-nowrap border-b-2 px-2.5 text-small no-underline transition-colors ${
                  active ? "border-[var(--accent-400)] font-semibold text-bar-ink" : "border-transparent text-bar-muted hover:text-bar-ink"
                }`}
              >
                {t(p.key)}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

/**
 * An administrator is signed in as the user: say so on every page, and offer
 * the way out. Ending is a plain form post to the tenant, so the browser's
 * own session cookie comes back with the answer.
 */
function ImpersonationBanner() {
  const { me, slug } = useAccount();
  const { t, locale } = useI18n();
  if (!me?.impersonation) return null;
  const when = new Intl.DateTimeFormat(locale, { timeStyle: "short" }).format(new Date(me.impersonation.expires_at));
  return (
    <div role="status" className="border-b border-line bg-[color-mix(in_oklab,var(--accent)_14%,var(--paper))]">
      <div className="mx-auto flex w-full max-w-3xl flex-wrap items-center justify-between gap-3 px-4 py-2.5 sm:px-6">
        <p className="flex min-w-0 items-center gap-2 text-body text-ink">
          <UserRoundCog className="size-4 shrink-0 text-link" aria-hidden />
          <span>{t("account.impersonation_banner", { admin: me.impersonation.impersonator, user: me.email ?? me.username, when })}</span>
        </p>
        <form method="post" action={`${tenantBase(slug)}/impersonation/end`} onSubmit={() => accountStore.end(null)}>
          <button type="submit" className="inline-flex min-h-9 items-center rounded-[var(--radius)] bg-accent px-3 text-small font-medium text-accent-ink hover:brightness-110">
            {t("account.impersonation_end")}
          </button>
        </form>
      </div>
    </div>
  );
}

/**
 * The frame (design/README.md "Account"): a dark header with the tenant
 * mark, the person's email, the theme switch (when the tenant allows it)
 * and sign-out, with the tabs along its bottom edge; then the page, whose
 * sections are cards.
 */
function Frame({ children }: { children: ReactNode }) {
  const { me, signOut } = useAccount();
  const { t } = useI18n();
  const name = me?.tenant.display_name ?? "";
  return (
    <div className="min-h-screen bg-ground">
      <a href="#main" className="skip-link">
        {t("common.skip_to_content")}
      </a>
      <ImpersonationBanner />
      <header className="console-bar">
        <div className="mx-auto flex h-14 w-full max-w-4xl items-center justify-between gap-3 px-4 sm:px-5">
          <div className="flex min-w-0 items-center gap-2.5">
            <span aria-hidden className="flex size-[1.625rem] shrink-0 items-center justify-center rounded-[7px] bg-[linear-gradient(135deg,var(--accent-500),var(--contrast-500))] text-white">
              <ShieldCheck className="size-3.5" />
            </span>
            <span className="font-display truncate text-md font-bold tracking-[-0.02em] text-bar-ink">{name}</span>
          </div>
          <div className="flex shrink-0 items-center gap-2.5">
            <span className="hidden text-small text-bar-muted sm:inline">{me?.email ?? me?.username}</span>
            <ThemeSwitch surface="bar" labels={{ group: t("common.theme"), system: t("common.theme_system"), light: t("common.theme_light"), dark: t("common.theme_dark") }} />
            <button
              type="button"
              onClick={signOut}
              className="inline-flex min-h-7 items-center gap-1.5 rounded-[var(--radius)] border border-[var(--bar-line)] px-2.5 text-caption font-medium text-bar-ink hover:bg-[var(--bar-field)]"
            >
              <LogOut className="size-3.5" aria-hidden />
              {t("account.sign_out")}
            </button>
          </div>
        </div>
        <Nav />
      </header>
      <main id="main" tabIndex={-1} className="account-cards mx-auto w-full max-w-4xl px-4 py-6 sm:px-5 sm:py-7">
        {children}
      </main>
      <p className="pb-6 text-center text-small text-muted">{t("common.powered_by")}</p>
    </div>
  );
}

/** Signed out: the tenant to sign in through (from `?tenant=`, else the last one). */
function SignIn() {
  const { signIn, notice } = useAccount();
  const { t } = useI18n();
  const params = useSearchParams();
  const [tenant, setTenant] = useState(() => params.get("tenant") ?? lastTenant() ?? "");
  const impersonating = params.get("impersonate") === "1" && isValidSlug(tenant);
  const [busy, setBusy] = useState(impersonating);
  const [problem, setProblem] = useState<string | null>(null);

  // An administrator's browser, just given a session as the user: sign in
  // through it at once. Coming back lands on the plain console page, so this
  // happens once per arrival.
  const started = useRef(false);
  useEffect(() => {
    if (!impersonating || started.current) return;
    started.current = true;
    signIn(tenant, "/account/").catch((err: unknown) => {
      setProblem(err instanceof AuthError ? err.message : t("account.sign_in_failed"));
      setBusy(false);
    });
  }, [impersonating, signIn, tenant, t]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const slug = tenant.trim().toLowerCase();
    if (!isValidSlug(slug)) {
      setProblem(t("account.invalid_tenant"));
      return;
    }
    setBusy(true);
    setProblem(null);
    try {
      await signIn(slug);
    } catch (err) {
      setProblem(err instanceof AuthError ? err.message : t("account.sign_in_failed"));
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-10">
      <main className="card-in w-full max-w-[24rem] rounded-[calc(var(--radius)+4px)] border border-line bg-paper p-6 sm:p-8">
        <h1 className="text-2xl font-semibold leading-tight tracking-[-0.01em] text-ink">{t("account.sign_in_title")}</h1>
        <p className="mt-1.5 text-lead text-muted">{t("account.sign_in_description")}</p>
        <form onSubmit={submit} className="mt-6 flex flex-col gap-4" noValidate>
          {(problem ?? notice) && <Alert tone="error">{problem ?? notice}</Alert>}
          <TextField label={t("account.tenant")} value={tenant} onChange={(e) => setTenant(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} required />
          <Button type="submit" busy={busy}>
            {t("common.continue")}
          </Button>
        </form>
      </main>
      <p className="mt-6 text-small text-muted">{t("common.powered_by")}</p>
    </div>
  );
}
