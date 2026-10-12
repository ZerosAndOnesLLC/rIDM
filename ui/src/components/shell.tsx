"use client";

import { useEffect, type ReactNode } from "react";
import { ThemeSwitch } from "@/components/base/theme-switch";
import { useI18n } from "@/i18n/provider";
import { bundles, displayName, normalize } from "@/i18n";
import { TenantProvider, useTenant } from "@/lib/tenant";
import { useSkin } from "@/lib/theme/provider";
import { Alert, Spinner } from "./ui";

/**
 * The frame every end-user page shares (design/README.md "Sign-in"). With
 * the Signal v2 skin and a headline set by the tenant, the page splits on
 * desktop: a brand panel (radial primary gradient with a contrast bloom,
 * the tenant's name, headline and tagline) beside the form; otherwise, and
 * on phones, the form alone in one card under the tenant mark. The footer
 * carries the tenant's links, the language switcher and the light/dark
 * switch when the tenant allows it.
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

function Frame({ locale, locales, children }: { locale?: string | null; locales?: string[]; children: ReactNode }) {
  const { tenant, problem, loading } = useTenant();
  const i18n = useI18n();
  const { t, setLocale } = i18n;
  const skin = useSkin();

  useEffect(() => {
    if (locale) setLocale(locale);
  }, [locale, setLocale]);

  // Only languages the UI can actually show; the server may negotiate more.
  const choices = (locales ?? tenant?.locale.supported ?? []).filter((c) => {
    const n = normalize(c);
    return n !== null && (n in bundles || n.split("-")[0]! in bundles);
  });
  const headline = tenant?.branding.headline?.trim() || null;
  const split = skin === "signal-v2" && Boolean(headline);

  const mark = tenant?.branding.logo_url ? (
    // Tenant-supplied asset; next/image cannot optimise it in a static export.
    // eslint-disable-next-line @next/next/no-img-element
    <img src={tenant.branding.logo_url} alt="" className="max-h-10 max-w-[10rem] object-contain" />
  ) : tenant ? (
    <span aria-hidden className="flex size-9 items-center justify-center rounded-[10px] bg-[linear-gradient(135deg,var(--accent-500),var(--contrast-500))] text-lead font-bold text-white">
      {tenant.display_name.slice(0, 1).toUpperCase()}
    </span>
  ) : null;

  const content =
    problem === "missing" ? (
      <Alert tone="error">{t("error.no_tenant")}</Alert>
    ) : problem === "unknown" ? (
      <Alert tone="error">{t("error.unknown_tenant")}</Alert>
    ) : problem === "error" ? (
      <Alert tone="error">{t("common.error_network")}</Alert>
    ) : loading ? (
      <Spinner label={t("common.loading")} />
    ) : (
      children
    );

  const footer = (
    <footer className={`mt-6 flex w-full flex-wrap items-center gap-x-4 gap-y-2 text-small text-muted ${split ? "max-w-[24rem]" : "max-w-[26rem]"}`}>
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
      <span className="ms-auto flex items-center gap-2.5">
        {choices.length > 1 && (
          <label className="flex items-center gap-1.5">
            <span className="sr-only">{t("common.language")}</span>
            <select value={i18n.locale} onChange={(e) => setLocale(e.target.value)} className="min-h-7 rounded-[6px] border border-line bg-paper px-1.5 text-md text-ink sm:text-caption">
              {choices.map((c) => (
                <option key={c} value={c}>
                  {displayName(c)}
                </option>
              ))}
            </select>
          </label>
        )}
        <ThemeSwitch labels={{ group: t("common.theme"), system: t("common.theme_system"), light: t("common.theme_light"), dark: t("common.theme_dark") }} />
        <span>{t("common.powered_by")}</span>
      </span>
    </footer>
  );

  if (split && tenant) {
    return (
      <div className="min-h-screen md:grid md:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <a href="#main" className="skip-link">
          {t("common.skip_to_content")}
        </a>
        <aside className="relative hidden overflow-hidden bg-[radial-gradient(120%_90%_at_20%_10%,var(--accent-600),var(--accent-900)_70%)] p-10 text-white md:flex md:flex-col md:justify-between">
          <span aria-hidden className="pointer-events-none absolute -end-[20%] -bottom-[30%] aspect-square w-[70%] rounded-full bg-[radial-gradient(circle,color-mix(in_oklab,var(--contrast-500)_55%,transparent),transparent_70%)] blur-[10px]" />
          <div className="font-display relative flex items-center gap-3 text-[1.25rem] font-bold tracking-[-0.02em]">
            <span aria-hidden className="flex size-[2.375rem] items-center justify-center rounded-[10px] border border-white/25 bg-white/15 text-md">
              {tenant.branding.logo_url ? (
                // eslint-disable-next-line @next/next/no-img-element -- tenant asset
                <img src={tenant.branding.logo_url} alt="" className="max-h-7 max-w-7 object-contain" />
              ) : (
                tenant.display_name.slice(0, 1).toUpperCase()
              )}
            </span>
            {tenant.display_name}
          </div>
          <div className="relative">
            <p className="font-display max-w-[16ch] text-[2.125rem] font-semibold leading-[1.1] tracking-[-0.02em]">{headline}</p>
            {tenant.branding.tagline && <p className="mt-3 max-w-[38ch] text-lead text-white/85">{tenant.branding.tagline}</p>}
          </div>
          <span />
        </aside>
        <div className="flex min-h-screen flex-col items-center justify-center px-4 py-8 sm:px-6 sm:py-10">
          <header className="mb-6 flex w-full max-w-[24rem] items-center gap-3 md:hidden">
            {mark}
            <span className="text-md font-semibold text-ink">{tenant.display_name}</span>
          </header>
          <main id="main" tabIndex={-1} className="card-in w-full max-w-[24rem]">
            {content}
          </main>
          {footer}
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center px-4 py-8 sm:py-14">
      <a href="#main" className="skip-link">
        {t("common.skip_to_content")}
      </a>
      <header className="mb-6 flex w-full max-w-[26rem] items-center gap-3">
        {mark}
        <span className="text-md font-semibold text-ink">{tenant?.display_name ?? ""}</span>
      </header>
      <main id="main" tabIndex={-1} className="card-in w-full max-w-[26rem] rounded-[var(--radius-lg)] border border-line bg-paper p-6 shadow-sheet sm:p-8">
        {content}
      </main>
      {footer}
    </div>
  );
}
