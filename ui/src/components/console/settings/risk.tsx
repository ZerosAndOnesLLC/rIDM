"use client";

import { Field, NumberInput, Section, Toggle } from "@/components/console/form";
import { useSettingsEditor } from "./context";

/**
 * Risk-based adaptive authentication: what each signal a sign-in raises is
 * worth, and the two scores at which the second factor is demanded or the
 * sign-in refused. The weights and thresholds only matter while the policy
 * is on, so they are shown but disabled until it is.
 */
export function RiskSection() {
  const { draft, editable, update } = useSettingsEditor();
  const risk = draft.settings.risk;
  const on = editable && risk.enabled;
  const weights = risk.weights;
  // What the current weights would score if every signal fired at once: the
  // number to read the two thresholds against.
  const most = weights.new_device + weights.new_country + weights.impossible_travel + weights.velocity;

  const weight = (key: keyof typeof weights, label: string, hint: string) => (
    <Field key={key} label={label} hint={hint}>
      {(id, by) => (
        <NumberInput
          id={id}
          describedBy={by}
          value={weights[key]}
          min={0}
          max={1000}
          disabled={!on}
          onValue={(v) => v !== null && update({ risk: { weights: { [key]: v } } })}
          unit="points"
        />
      )}
    </Field>
  );

  return (
    <Section
      id="risk"
      title="Adaptive authentication"
      description="Score every sign-in against what the user has done before, and ask for more — or refuse — when it looks unusual. Countries and coordinates come from the deployment's geo source; without one, only the device and velocity signals can fire."
    >
      <div className="flex flex-col gap-1 sm:col-span-2">
        <Toggle
          label="Score sign-ins"
          hint="Off: sign-ins are never scored and no locations are recorded."
          checked={risk.enabled}
          disabled={!editable}
          onChange={(v) => update({ risk: { enabled: v } })}
        />
      </div>

      <div className="flex flex-col gap-1 sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Signals</h3>
        <p className="text-[0.8125rem] text-muted">
          Each signal a sign-in raises adds its points. Everything together scores {most}.
        </p>
      </div>
      {weight("new_device", "New device", "The browser has no trusted-device cookie and the user has never signed in from it. A first-ever sign-in is not new.")}
      {weight("new_country", "New country", "The user has never signed in from this country before.")}
      {weight("impossible_travel", "Impossible travel", "The distance from where the user was last seen cannot be covered in the time since.")}
      {weight("velocity", "Failure velocity", "The address is behind an unusual number of recent failed sign-ins.")}

      <div className="flex flex-col gap-1 sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Thresholds</h3>
      </div>
      <Field label="Ask for a second factor at" hint="Score at which the sign-in must pass a second step, whatever the two-step policy says and even on a trusted device. 0 never steps up.">
        {(id, by) => (
          <NumberInput id={id} describedBy={by} value={risk.step_up_at} min={0} max={10000} disabled={!on} onValue={(v) => v !== null && update({ risk: { step_up_at: v } })} unit="points" />
        )}
      </Field>
      <Field label="Refuse the sign-in at" hint="Score at which the sign-in is refused: the client is told access_denied and no session is opened. 0 never refuses." error={risk.block_at > 0 && risk.step_up_at > 0 && risk.block_at < risk.step_up_at ? "Refusing below the step-up score means a second factor is never asked for." : null}>
        {(id, by) => (
          <NumberInput id={id} describedBy={by} value={risk.block_at} min={0} max={10000} disabled={!on} onValue={(v) => v !== null && update({ risk: { block_at: v } })} unit="points" />
        )}
      </Field>

      <div className="flex flex-col gap-1 sm:col-span-2">
        <h3 className="text-[0.8125rem] font-medium text-ink">Signal tuning</h3>
      </div>
      <Field label="Impossible travel above" hint="Travelling faster than this between two sign-ins is impossible. 0 switches the signal off.">
        {(id, by) => (
          <NumberInput id={id} describedBy={by} value={risk.impossible_travel_kmh} min={0} max={100000} disabled={!on} onValue={(v) => v !== null && update({ risk: { impossible_travel_kmh: v } })} unit="km/h" />
        )}
      </Field>
      <Field label="Velocity window" hint="How far back failed sign-ins from the address are counted.">
        {(id, by) => (
          <NumberInput id={id} describedBy={by} value={risk.velocity_window_minutes} min={1} max={1440} disabled={!on} onValue={(v) => v !== null && update({ risk: { velocity_window_minutes: v } })} unit="min" />
        )}
      </Field>
      <Field label="Velocity failures" hint="Failures from the address within the window that raise the signal. 0 switches it off.">
        {(id, by) => (
          <NumberInput id={id} describedBy={by} value={risk.velocity_max_failures} min={0} max={10000} disabled={!on} onValue={(v) => v !== null && update({ risk: { velocity_max_failures: v } })} unit="failures" />
        )}
      </Field>
    </Section>
  );
}
