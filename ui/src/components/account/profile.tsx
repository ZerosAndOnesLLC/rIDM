"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useI18n } from "@/i18n/provider";
import { AttributeField } from "@/components/console/users/attributes";
import { Field, SaveIndicator, SelectInput, TextInput } from "@/components/console/form";
import { Card } from "@/components/console/ui";
import { useAccount } from "@/lib/account/session";
import { useAutoSave } from "@/lib/console/autosave";
import type { Schemas } from "@api/client";

export type AccountProfile = Schemas["Profile"];
type ProfilePatch = Schemas["ProfilePatch"];

export function useProfile() {
  const { client, slug } = useAccount();
  return useQuery({
    queryKey: ["account", "profile", slug],
    queryFn: async () => {
      const { data, error } = await client.GET("/t/{slug}/account/profile", { params: { path: { slug } } });
      if (error) throw error;
      return data;
    },
  });
}

/** The profile as the tenant's schema shapes it, saved as it is edited. */
export function Profile() {
  const { t } = useI18n();
  const profile = useProfile();
  if (profile.isError) return <Card title={t("account.profile")}>{t("account.error_generic")}</Card>;
  if (!profile.data) return <Card title={t("account.profile")}>{t("common.loading")}</Card>;
  // Keyed by the stored document so a failed save starts over from it.
  return <ProfileForm key={profile.dataUpdatedAt} profile={profile.data} />;
}

type Draft = { attributes: Record<string, unknown>; locale: string | null };

function draftOf(p: AccountProfile): Draft {
  return { attributes: { ...((p.attributes as Record<string, unknown> | null) ?? {}) }, locale: p.locale ?? null };
}

/** The attributes the user may edit, whole: the API replaces that set on every patch. */
function editable(p: AccountProfile, attributes: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const def of p.schema) {
    if (def.editable_by !== "user") continue;
    const v = attributes[def.name];
    if (v !== undefined) out[def.name] = v;
  }
  return out;
}

function ProfileForm({ profile }: { profile: AccountProfile }) {
  const { client, slug } = useAccount();
  const { t } = useI18n();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Draft>(() => draftOf(profile));
  // What is stored, in the shape patches take: the user-editable attributes
  // and the locale.
  const baseline = useMemo(() => {
    const stored = draftOf(profile);
    return { attributes: editable(profile, stored.attributes), locale: stored.locale };
  }, [profile]);

  const save = useAutoSave(async (patch: ProfilePatch) => {
    const { error } = await client.PATCH("/t/{slug}/account/profile", { params: { path: { slug } }, body: patch });
    if (error) {
      const p = error as { detail?: string; errors?: { field: string; message: string }[] };
      const first = p.errors?.[0];
      // On failure the form is rebuilt from the stored document.
      void qc.invalidateQueries({ queryKey: ["account", "profile", slug] });
      throw new Error(first ? `${first.field.replace(/^attributes\./, "")} ${first.message}` : (p.detail ?? t("account.error_generic")));
    }
  }, { baseline });

  const setAttribute = (name: string, value: unknown) => {
    const attributes = { ...draft.attributes, [name]: value };
    setDraft({ ...draft, attributes });
    save.queue({ attributes: editable(profile, attributes) } as ProfilePatch);
  };
  const setLocale = (locale: string | null) => {
    setDraft({ ...draft, locale });
    save.queue({ locale } as ProfilePatch);
  };

  const fields = profile.schema;
  return (
    <Card title={t("account.profile_title")} actions={<SaveIndicator status={save.status} error={save.error} />}>
      <p className="text-[0.875rem] text-muted">{t("account.profile_description")}</p>
      <div className="mt-4 grid gap-5 sm:grid-cols-2">
        <Field label={t("account.username")} hint={t("account.username_hint")}>
          {(id, by) => <TextInput id={id} aria-describedby={by} value={profile.username} readOnly disabled />}
        </Field>
        <Field label={t("account.locale")} hint={t("account.locale_hint")}>
          {(id, by) => (
            <SelectInput id={id} aria-describedby={by} value={draft.locale ?? ""} onChange={(e) => setLocale(e.target.value === "" ? null : e.target.value)}>
              <option value="">{t("account.locale_default")}</option>
              {profile.locales.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </SelectInput>
          )}
        </Field>
        {fields.map((def) => (
          <AttributeField key={def.name} def={def} value={draft.attributes[def.name] ?? null} disabled={def.editable_by !== "user"} onChange={(v) => setAttribute(def.name, v)} />
        ))}
      </div>
      {fields.length === 0 && <p className="mt-4 text-[0.875rem] text-muted">{t("account.profile_no_fields")}</p>}
    </Card>
  );
}
