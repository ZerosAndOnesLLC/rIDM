"use client";

import { LogOut, ShieldCheck, UserRoundCog } from "lucide-react";
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
    <nav aria-label={t("account.nav_label")} className="mx-auto w-full max-w-3xl px-4 sm:px-6">
      <ul className="-mb-px flex gap-1 overflow-x-auto">
        {PAGES.map((p) => {
          const active = here === p.href;
          return (
            <li key={p.href}>
              <Link
                href={p.href}
                aria-current={active ? "page" : undefined}
                className={`inline-flex min-h-10 items-center border-b-2 px-3 text-[0.875rem] font-medium transition-colors ${
                  active ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"
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
        <p className="flex min-w-0 items-center gap-2 text-[0.875rem] text-ink">
          <UserRoundCog className="size-4 shrink-0 text-link" aria-hidden />
          <span>{t("account.impersonation_banner", { admin: me.impersonation.impersonator, user: me.email ?? me.username, when })}</span>
        </p>
        <form method="post" action={`${tenantBase(slug)}/impersonation/end`} onSubmit={() => accountStore.end(null)}>
          <button type="submit" className="inline-flex min-h-9 items-center rounded-[var(--radius)] bg-accent px-3 text-[0.8125rem] font-medium text-accent-ink hover:brightness-110">
            {t("account.impersonation_end")}
          </button>
        </form>
      </div>
    </div>
  );
}

function Frame({ children }: { children: ReactNode }) {
  const { me, signOut } = useAccount();
  const { t } = useI18n();
  return (
    <div className="min-h-screen bg-ground">
      <ImpersonationBanner />
      <header className="border-b border-line bg-paper">
        <div className="mx-auto flex w-full max-w-3xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-2.5">
            <span aria-hidden className="flex size-8 items-center justify-center rounded-lg bg-accent text-accent-ink">
              <ShieldCheck className="size-4" />
            </span>
            <span className="text-[0.9375rem] font-semibold text-ink">{me?.tenant.display_name}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden text-[0.875rem] text-muted sm:inline">{me?.email ?? me?.username}</span>
            <button
              type="button"
              onClick={signOut}
              className="inline-flex min-h-9 items-center gap-1.5 rounded-[var(--radius)] border border-line px-3 text-[0.8125rem] font-medium text-ink hover:bg-ground"
            >
              <LogOut className="size-3.5" aria-hidden />
              {t("account.sign_out")}
            </button>
          </div>
        </div>
        <Nav />
      </header>
      <main className="mx-auto w-full max-w-3xl px-4 py-6 sm:px-6 sm:py-8">{children}</main>
      <p className="pb-6 text-center text-[0.8125rem] text-muted">{t("common.powered_by")}</p>
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
        <h1 className="text-[1.5rem] font-semibold leading-tight tracking-[-0.01em] text-ink">{t("account.sign_in_title")}</h1>
        <p className="mt-1.5 text-[0.9375rem] text-muted">{t("account.sign_in_description")}</p>
        <form onSubmit={submit} className="mt-6 flex flex-col gap-4" noValidate>
          {(problem ?? notice) && <Alert tone="error">{problem ?? notice}</Alert>}
          <TextField label={t("account.tenant")} value={tenant} onChange={(e) => setTenant(e.target.value)} autoComplete="off" autoCapitalize="none" spellCheck={false} required />
          <Button type="submit" busy={busy}>
            {t("common.continue")}
          </Button>
        </form>
      </main>
      <p className="mt-6 text-[0.8125rem] text-muted">{t("common.powered_by")}</p>
    </div>
  );
}
