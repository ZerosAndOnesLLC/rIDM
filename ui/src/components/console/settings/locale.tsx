"use client";

import { Field, Section, SelectInput, TagsInput, Toggle } from "@/components/console/form";
import { displayName, normalize } from "@/i18n";
import { useSettingsEditor } from "./context";

export function LocaleSection() {
  const { draft, editable, update } = useSettingsEditor();
  const { locale, notifications } = draft.settings;
  const supported = locale.supported.length ? locale.supported : [locale.default];
  return (
    <Section id="locale" title="Locale & notices" description="Languages offered on the login pages and which security notices users receive.">
      <Field label="Supported languages" hint="BCP 47 tags; Enter adds one. The UI ships English and falls back to it.">
        {(id, by) => (
          <TagsInput
            id={id}
            describedBy={by}
            value={locale.supported}
            onChange={(v) => {
              const next = v.length ? v : ["en"];
              update({ locale: { supported: next, default: next.includes(locale.default) ? locale.default : next[0]! } });
            }}
            placeholder="en, de, fr-CA"
            normalize={(s) => normalize(s) ?? ""}
          />
        )}
      </Field>
      <Field label="Default language">
        {(id) => (
          <SelectInput id={id} value={locale.default} disabled={!editable} onChange={(e) => update({ locale: { default: e.target.value } })}>
            {supported.map((l) => (
              <option key={l} value={l}>
                {displayName(l)} ({l})
              </option>
            ))}
          </SelectInput>
        )}
      </Field>
      <div className="flex flex-col gap-1 sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Security notices</h3>
        <Toggle label="Sign-in from a new device" checked={notifications.new_device} disabled={!editable} onChange={(v) => update({ notifications: { new_device: v } })} />
        <Toggle label="Password changed" checked={notifications.password_changed} disabled={!editable} onChange={(v) => update({ notifications: { password_changed: v } })} />
        <Toggle label="Two-step verification changed" checked={notifications.mfa_changed} disabled={!editable} onChange={(v) => update({ notifications: { mfa_changed: v } })} />
        <Toggle label="Email address changed" hint="Sent to the previous address." checked={notifications.email_changed} disabled={!editable} onChange={(v) => update({ notifications: { email_changed: v } })} />
      </div>
    </Section>
  );
}
