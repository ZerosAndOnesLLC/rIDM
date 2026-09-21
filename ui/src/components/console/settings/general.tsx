"use client";

import Link from "next/link";
import { Field, Section, SelectInput, TextInput } from "@/components/console/form";
import { useSettingsEditor } from "./context";

export function GeneralSection() {
  const { draft, editable, update, updateTenant } = useSettingsEditor();
  const flags = Object.keys(draft.settings.features ?? {}).length;
  const isMaster = draft.slug === "master";

  return (
    <Section id="general" title="General" description="Name and availability of this tenant.">
      <Field label="Display name" hint="Shown on the login pages and in the console.">
        {(id, by) => (
          <TextInput id={id} aria-describedby={by} value={draft.display_name} disabled={!editable} onChange={(e) => updateTenant({ display_name: e.target.value })} />
        )}
      </Field>
      <Field label="Status" hint={isMaster ? "The master tenant is always active." : "A disabled tenant refuses every sign-in and token request."}>
        {(id, by) => (
          <SelectInput id={id} aria-describedby={by} value={draft.status} disabled={!editable || isMaster} onChange={(e) => updateTenant({ status: e.target.value as "active" | "disabled" })}>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </SelectInput>
        )}
      </Field>
      <Field label="Slug" hint="Part of the issuer URL; it cannot change.">
        {(id) => <TextInput id={id} value={draft.slug} readOnly disabled />}
      </Field>
      <Field label="Custom domain" hint="Serve this tenant on its own host: point the name at rIDM (with TLS) and its issuer becomes https://<host>, with discovery, JWKS and every endpoint answering there without the /t/<slug> prefix.">
        {(id, by) => (
          <TextInput
            id={id}
            aria-describedby={by}
            value={draft.settings.custom_domain ?? ""}
            placeholder="login.example.com"
            disabled={!editable}
            onChange={(e) => update({ custom_domain: e.target.value.trim() === "" ? null : e.target.value.trim() })}
          />
        )}
      </Field>
      <div className="sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Feature flags</h3>
        <p className="text-[0.8125rem] text-muted">
          {flags === 0 ? "None yet. " : `${flags} flag${flags === 1 ? "" : "s"}. `}
          <Link href={`/console/features/?tenant=${encodeURIComponent(draft.slug)}`} className="text-link underline underline-offset-4">
            Manage feature flags
          </Link>
        </p>
      </div>
    </Section>
  );
}
