"use client";

import { useEffect, type ReactNode } from "react";
import { useI18n } from "@/i18n/provider";
import { bundles, displayName, normalize } from "@/i18n";
import { TenantProvider, useTenant } from "@/lib/tenant";
import { Alert, Spinner } from "./ui";

/**
 * The frame every end-user page shares: tenant mark on top, one card, quiet
 * footer with the tenant's links and a language switcher. The card is the
 * only surface; the tenant's colour appears on the primary action and focus
 * rings, nowhere else.
 */
export function AuthShell({
  slug,
  locale,
  locales,
  preview = false,
  children,
}: {
  slug: string | null;
  /** Locale negotiated by the server for this request, once known. */
  locale?: string | null;
  locales?: string[];
  /** Framed by the console's branding editor: follow its live overrides. */
  preview?: boolean;
  children: ReactNode;
}) {
  return (
    <TenantProvider slug={slug} preview={preview}>
      <Frame locale={locale} locales={locales}>
        {children}
      </Frame>
    </TenantProvider>
  );
}

function Frame({
  locale,
  locales,
  children,
}: {
  locale?: string | null;
  locales?: string[];
  children: ReactNode;
}) {
  const { tenant, problem, loading } = useTenant();
  const i18n = useI18n();
  const { t, setLocale } = i18n;

  useEffect(() => {
    if (locale) setLocale(locale);
  }, [locale, setLocale]);

  // Only languages the UI can actually show; the server may negotiate more.
  const choices = (locales ?? tenant?.locale.supported ?? []).filter((c) => {
    const n = normalize(c);
    return n !== null && (n in bundles || n.split("-")[0]! in bundles);
  });

  return (
    <div className="flex min-h-screen flex-col items-center px-4 py-8 sm:py-14">
      <header className="mb-6 flex w-full max-w-[26rem] items-center gap-3">
        {tenant?.branding.logo_url ? (
          // Tenant-supplied asset; next/image cannot optimise it in a static export.
          // eslint-disable-next-line @next/next/no-img-element
          <img src={tenant.branding.logo_url} alt="" className="max-h-10 max-w-[10rem] object-contain" />
        ) : (
          tenant && (
            <span
              aria-hidden
              className="flex size-9 items-center justify-center rounded-lg bg-accent text-[0.9375rem] font-semibold text-accent-ink"
            >
              {tenant.display_name.slice(0, 1).toUpperCase()}
            </span>
          )
        )}
        <span className="text-[1.0625rem] font-semibold text-ink">{tenant?.display_name ?? ""}</span>
      </header>

      <main className="card-in w-full max-w-[26rem] rounded-[calc(var(--radius)+4px)] border border-line bg-paper p-6 sm:p-8">
        {problem === "missing" ? (
          <Alert tone="error">{t("error.no_tenant")}</Alert>
        ) : problem === "unknown" ? (
          <Alert tone="error">{t("error.unknown_tenant")}</Alert>
        ) : problem === "error" ? (
          <Alert tone="error">{t("common.error_network")}</Alert>
        ) : loading ? (
          <Spinner label={t("common.loading")} />
        ) : (
          children
        )}
      </main>

      <footer className="mt-6 flex w-full max-w-[26rem] flex-wrap items-center gap-x-4 gap-y-2 text-[0.8125rem] text-muted">
        {tenant?.branding.links.map((l) => (
          <a key={l.url} href={l.url} className="hover:text-ink hover:underline underline-offset-4">
            {l.label}
          </a>
        ))}
        {tenant?.branding.support_url && (
          <a href={tenant.branding.support_url} className="hover:text-ink hover:underline underline-offset-4">
            {t("common.help")}
          </a>
        )}
        <span className="ms-auto flex items-center gap-2">
          {choices.length > 1 && (
            <label className="flex items-center gap-1.5">
              <span className="sr-only">{t("common.language")}</span>
              <select
                value={i18n.locale}
                onChange={(e) => setLocale(e.target.value)}
                className="rounded-md border border-line bg-paper px-2 py-1 text-[1rem] text-ink sm:text-[0.8125rem]"
              >
                {choices.map((c) => (
                  <option key={c} value={c}>
                    {displayName(c)}
                  </option>
                ))}
              </select>
            </label>
          )}
          <span>{t("common.powered_by")}</span>
        </span>
      </footer>
    </div>
  );
}
