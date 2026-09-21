"use client";

import { Field, NumberInput, Section, Toggle } from "@/components/console/form";
import { useSettingsEditor } from "./context";

/**
 * Whether administrators holding `ridm:users:impersonate` may sign in as this
 * tenant's users, and for how long at a time. Off by default.
 */
export function ImpersonationSection() {
  const { draft, editable, update } = useSettingsEditor();
  const policy = draft.settings.impersonation;
  return (
    <Section
      id="impersonation"
      title="Impersonation"
      description="Let administrators sign in as a user to see what they see. Each impersonation needs a reason and is audited from start to end. Tokens from the session name the administrator in an act claim. Users holding any admin permission can never be impersonated, and nobody impersonating a user can change their credentials or consent for them."
    >
      <div className="flex flex-col gap-1 sm:col-span-2">
        <Toggle
          label="Allow impersonation"
          hint="Only roles with the ridm:users:impersonate permission may use it. Among the built-in roles, that is Owner."
          checked={policy.enabled}
          disabled={!editable}
          onChange={(v) => update({ impersonation: { enabled: v } })}
        />
      </div>
      <Field label="Longest session" hint="An impersonated session ends by itself after this long, or sooner if the tenant's absolute session timeout is shorter.">
        {(id, by) => (
          <NumberInput
            id={id}
            describedBy={by}
            value={policy.max_minutes}
            min={1}
            max={480}
            disabled={!editable || !policy.enabled}
            onValue={(v) => v !== null && update({ impersonation: { max_minutes: v } })}
            unit="min"
          />
        )}
      </Field>
    </Section>
  );
}
