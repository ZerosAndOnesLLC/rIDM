"use client";

import { useState } from "react";
import { Field, Section, SelectInput, TextInput, Toggle } from "@/components/console/form";
import { Button } from "@/components/console/ui";
import { useSettingsEditor } from "./context";

export function GeneralSection() {
  const { draft, editable, update, updateTenant } = useSettingsEditor();
  const [flag, setFlag] = useState("");
  const features = draft.settings.features ?? {};
  const isMaster = draft.slug === "master";

  const addFlag = () => {
    const key = flag.trim();
    if (!key || key in features) return;
    update({ features: { [key]: true } });
    setFlag("");
  };

  return (
    <Section id="general" title="General" description="Name, availability and feature flags of this tenant.">
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
        <p className="text-[0.8125rem] text-muted">Free-form switches your deployment or its clients consult.</p>
        <div className="mt-3 flex flex-col divide-y divide-line rounded-[var(--radius)] border border-line px-4">
          {Object.keys(features).length === 0 && <p className="py-3 text-[0.875rem] text-muted">No flags yet.</p>}
          {Object.entries(features)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, on]) => (
              <div key={key} className="flex items-center gap-3">
                <div className="flex-1">
                  <Toggle label={key} checked={Boolean(on)} disabled={!editable} onChange={(v) => update({ features: { [key]: v } })} />
                </div>
                {editable && (
                  <Button variant="secondary" className="min-h-8 px-2.5 text-[0.8125rem]" onClick={() => update({ features: { [key]: null } })}>
                    Remove
                  </Button>
                )}
              </div>
            ))}
        </div>
        {editable && (
          <form
            className="mt-3 flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              addFlag();
            }}
          >
            <TextInput aria-label="New flag name" value={flag} onChange={(e) => setFlag(e.target.value)} placeholder="beta_dashboard" className="max-w-xs" />
            <Button type="submit" variant="secondary" disabled={!flag.trim()}>
              Add flag
            </Button>
          </form>
        )}
      </div>
    </Section>
  );
}
