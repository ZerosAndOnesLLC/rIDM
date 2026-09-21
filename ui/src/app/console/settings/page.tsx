"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useMemo, useState } from "react";
import { SaveIndicator } from "@/components/console/form";
import { AdvancedSection } from "@/components/console/settings/advanced";
import { BrandingSection } from "@/components/console/settings/branding";
import { SettingsContext, type SettingsEditor } from "@/components/console/settings/context";
import { DangerZone } from "@/components/console/settings/danger";
import { GeneralSection } from "@/components/console/settings/general";
import { LocaleSection } from "@/components/console/settings/locale";
import { PasswordsSection } from "@/components/console/settings/passwords";
import { ProfileSchemaSection } from "@/components/console/settings/profile";
import { RateLimitsSection } from "@/components/console/settings/ratelimits";
import { RiskSection } from "@/components/console/settings/risk";
import { SessionsSection } from "@/components/console/settings/sessions";
import { SignInSection } from "@/components/console/settings/signin";
import { PageHeader } from "@/components/console/ui";
import { Spinner } from "@/components/ui";
import { useAutoSave, type SaveOptions } from "@/lib/console/autosave";
import { useConsole } from "@/lib/console/session";
import { applySettings, SECTIONS, type SettingsPatch, type Tenant, type TenantPatch, type TenantPatchBody } from "@/lib/console/settings";
import { useConsoleTenant } from "@/lib/console/tenant";

/**
 * Every tenant setting on one page, saved as you go: each change patches
 * the draft at once and joins a merge patch that is sent when typing
 * pauses. A rejected save shows why and reloads the stored settings.
 */
export default function SettingsPage() {
  const slug = useConsoleTenant();
  const { client, can, me } = useConsole();
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["tenant", slug],
    enabled: Boolean(slug),
    queryFn: async () => {
      const { data, error } = await client.GET("/admin/tenants/{slug}", { params: { path: { slug: slug! } } });
      if (error) throw new Error(error.detail ?? error.title);
      return data;
    },
  });

  // The draft follows the stored tenant until the administrator edits it;
  // it is rebuilt when the tenant in view changes or a save is rejected.
  const [draft, setDraft] = useState<Tenant | null>(null);
  const [seenSlug, setSeenSlug] = useState(slug);
  const [resetCount, setResetCount] = useState(0);
  const [seenReset, setSeenReset] = useState(0);
  if (seenSlug !== slug) {
    setSeenSlug(slug);
    setDraft(null);
  }
  if (seenReset !== resetCount) {
    setSeenReset(resetCount);
    setDraft(query.data ?? null);
  }
  if (draft === null && query.data) setDraft(query.data);

  const save = useCallback(
    async (patch: TenantPatch, { keepalive }: SaveOptions) => {
      // The generated body type marks the nullable fields as present; a merge patch omits what it leaves alone.
      const { data, error } = await client.PATCH("/admin/tenants/{slug}", {
        params: { path: { slug: slug! } },
        body: patch as TenantPatchBody,
        keepalive,
      });
      if (error) {
        await qc.invalidateQueries({ queryKey: ["tenant", slug] });
        setResetCount((n) => n + 1);
        throw new Error(error.detail ?? error.title);
      }
      qc.setQueryData(["tenant", slug], data);
      void qc.invalidateQueries({ queryKey: ["tenants"] });
    },
    [client, qc, slug],
  );
  const { queue, status, error } = useAutoSave<TenantPatch>(save);

  const editable = can("ridm:tenants:write");
  const editor = useMemo<SettingsEditor | null>(
    () =>
      draft && {
        draft,
        editable,
        global: me?.scope === "global",
        update: (patch: SettingsPatch) => {
          setDraft((d) => (d ? applySettings(d, patch) : d));
          if (editable) queue({ settings: patch });
        },
        updateTenant: (patch) => {
          setDraft((d) => (d ? { ...d, ...patch } : d));
          if (editable) queue(patch);
        },
      },
    [draft, editable, me?.scope, queue],
  );

  if (query.isError) {
    return (
      <>
        <PageHeader title="Settings" />
        <p role="alert" className="text-[0.9rem] text-danger">
          {query.error.message}
        </p>
      </>
    );
  }
  if (!editor) return <Spinner label="Loading settings…" />;

  return (
    <SettingsContext.Provider value={editor}>
      <PageHeader title="Settings" sub={`${editor.draft.display_name} · ${editor.draft.slug}`} actions={<SaveIndicator status={status} error={error} />} />
      {!editable && (
        <p className="mb-4 rounded-[var(--radius)] bg-ground px-4 py-2.5 text-[0.875rem] text-muted" role="status">
          You can view these settings but not change them.
        </p>
      )}
      <div className="grid gap-6 lg:grid-cols-[11rem_minmax(0,1fr)]">
        <nav aria-label="Settings sections" className="lg:sticky lg:top-20 lg:self-start">
          <ul className="flex flex-wrap gap-1 lg:flex-col">
            {SECTIONS.map((s) => (
              <li key={s.id}>
                <a href={`#${s.id}`} className="block rounded-[var(--radius)] px-3 py-1.5 text-[0.875rem] text-muted hover:bg-paper hover:text-ink">
                  {s.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex min-w-0 flex-col gap-6">
          <GeneralSection />
          <SignInSection />
          <RiskSection />
          <ProfileSchemaSection tenant={editor.draft.slug} editable={editable} />
          <PasswordsSection />
          <RateLimitsSection />
          <SessionsSection />
          <BrandingSection />
          <LocaleSection />
          <AdvancedSection />
          {editor.global && can("ridm:tenants:delete") && editor.draft.slug !== "master" && <DangerZone slug={editor.draft.slug} />}
        </div>
      </div>
    </SettingsContext.Provider>
  );
}
