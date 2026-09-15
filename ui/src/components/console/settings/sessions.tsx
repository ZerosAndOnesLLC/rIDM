"use client";

import { Field, NumberInput, Section } from "@/components/console/form";
import { useSettingsEditor } from "./context";

export function SessionsSection() {
  const { draft, update } = useSettingsEditor();
  const s = draft.settings.session;
  const num = (key: keyof typeof s, label: string, hint: string, unit: string, min = 0) => (
    <Field key={key} label={label} hint={hint}>
      {(id, by) => <NumberInput id={id} describedBy={by} value={s[key]} min={min} onValue={(v) => v !== null && update({ session: { [key]: v } })} unit={unit} />}
    </Field>
  );
  return (
    <Section id="sessions" title="Sessions & tokens" description="Browser session lifetime and default token lifetimes (clients may set shorter ones).">
      {num("idle_timeout_secs", "Idle timeout", "A session ends after this long without activity.", "s", 60)}
      {num("absolute_timeout_secs", "Absolute timeout", "A session ends this long after sign-in regardless.", "s", 60)}
      {num("max_concurrent", "Concurrent sessions per user", "The oldest is revoked first; 0 = unlimited.", "")}
      {num("remember_device_days", "Remember a device for", "How long \"remember this device\" skips the second factor.", "days")}
      {num("access_token_ttl_secs", "Access token lifetime", "Default for clients without their own.", "s", 30)}
      {num("id_token_ttl_secs", "ID token lifetime", "", "s", 30)}
      {num("refresh_token_ttl_secs", "Refresh token lifetime", "Rotated on every use.", "s", 60)}
    </Section>
  );
}
